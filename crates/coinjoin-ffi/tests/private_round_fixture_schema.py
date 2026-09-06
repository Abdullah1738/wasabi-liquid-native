"""Stdlib-only schema gate for the ignored private native replay fixture."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import re
import copy
import unittest

sys.dont_write_bytecode = True
from public_round_fixture_schema import unique_object, validate

ALLOWED = {"private-manifest.json", "manifest.json", "preblind.pset", "intermediate.pset", "final.pset", "secrets.json", "round-facts.json", "requests.bin", "responses.bin", "SHA256SUMS"}


def frames(data):
    offset = 0
    result = []
    while offset < len(data):
        assert offset + 16 <= len(data)
        magic, version, op, length = struct.unpack_from(">IIII", data, offset)
        assert magic == 0x574C434A and version == 1 and length <= 1_048_576
        end = offset + 16 + length
        offset += 16
        fields = []
        while offset < end:
            assert offset + 4 <= end
            size, = struct.unpack_from(">I", data, offset)
            offset += 4
            assert offset + size <= end <= len(data)
            fields.append(data[offset:offset + size])
            offset += size
        assert offset == end
        result.append((op, fields))
    return result


def load_bundle():
    directory = Path(os.environ["WLCJ_PRIVATE_ROUND_FIXTURE_DIR"]).resolve(strict=True)
    root = Path(__file__).resolve().parents[3] / "tmp"
    assert directory.is_relative_to(root.resolve()) and directory != root.resolve()
    assert directory.stat().st_mode & 0o777 == 0o700
    assert {path.name for path in directory.iterdir()} == ALLOWED
    for path in directory.iterdir():
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1_048_576
        assert path.stat().st_mode & 0o777 == 0o600
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def validate_bundle(data):
    assert set(data) == ALLOWED
    load = lambda name: json.loads(data[name], object_pairs_hook=unique_object)
    manifest = load("private-manifest.json")
    assert set(manifest) == {"schema", "private_test_only", "source_commit", "source_tree_hash", "required_ops", "psets", "request_file", "response_file", "public_manifest_file", "secret_file", "facts_file"}
    assert manifest["schema"] == "wlcj-private-round-v1" and manifest["private_test_only"] is True
    assert all(re.fullmatch("[0-9a-f]{40}", manifest[name]) for name in ("source_commit", "source_tree_hash"))
    assert manifest["required_ops"] == [4, 5, 8, 9, 10, 11, 12, 13]
    assert manifest["psets"] == ["preblind.pset", "intermediate.pset", "final.pset"]
    assert [manifest[name] for name in ("request_file", "response_file", "public_manifest_file", "secret_file", "facts_file")] == ["requests.bin", "responses.bin", "manifest.json", "secrets.json", "round-facts.json"]
    public = load("manifest.json")
    validate(public, {name: data[name] for name in ("preblind.pset", "final.pset")})
    secrets = load("secrets.json")
    assert set(secrets) == {"private_test_only", "participants"} and secrets["private_test_only"] is True
    assert len(secrets["participants"]) == 2
    for participant in secrets["participants"]:
        assert set(participant) == {"receiver_secret_key_hex", "spend_secret_key_hex", "input_asset_bf_hex", "input_value_bf_hex", "output_asset_bf_hex", "output_value_bf_hex", "input_credential_r1_hex", "output_credential_r1_hex"}
        for value in participant.values():
            assert re.fullmatch("[0-9a-f]{64}", value)
    facts = load("round-facts.json")
    assert set(facts) == {"private_test_only", "role_map_hex", "input_facts", "output_facts", "contexts_hex", "digests_hex", "entropy_hex", "assembled_txid_wire_hex"}
    assert facts["private_test_only"] is True and len(facts["input_facts"]) == len(facts["output_facts"]) == 2
    assert len(facts["contexts_hex"]) == len(facts["digests_hex"]) == 3
    assert len(facts["entropy_hex"]) == 5 and all(len(bytes.fromhex(value)) == 32 for value in facts["entropy_hex"])
    assert facts["input_facts"] == public["inputs"] and facts["output_facts"] == public["outputs"]
    assert facts["role_map_hex"] == public["role_map_hex"]
    assert facts["contexts_hex"] == [state["context_hex"] for state in public["states"]]
    assert facts["digests_hex"] == [state["digest"] for state in public["states"]]
    assert facts["assembled_txid_wire_hex"] == public["assembled_txid_wire_hex"]
    requests = frames(data["requests.bin"])
    responses = frames(data["responses.bin"])
    operations = [op for op, _ in requests]
    assert operations == [1, 4, 1, 5, 1, 6, 13, 8, 2, 9, 3, 10, 7, 13, 8, 2, 9, 3, 10, 7, 11, 11, 12]
    assert [op for op, _ in responses] == operations
    psets = [data[name] for name in manifest["psets"]]
    assert requests[0][1] == [psets[0], bytes.fromhex(facts["contexts_hex"][0])]
    assert responses[1][1][0] == psets[1] and responses[3][1][0] == psets[2]
    assert requests[1][1][0] == requests[3][1][0] == psets[0]
    assert requests[3][1][2] == psets[1]
    registration_indices = {8: [], 9: []}
    for (op, fields), (_, result) in zip(requests, responses):
        if op in (4, 5, 8, 9, 10):
            entropy_index, field_index = {4: (0, 3), 5: (1, 4), 8: (2, 6), 9: (3, 6), 10: (4, 3)}[op]
            assert fields[field_index] == bytes.fromhex(facts["entropy_hex"][entropy_index])
        if op in (8, 9):
            assert len(fields) == (7 if op == 8 else 9)
            # The context binds the witness to its registration kind and participant.
            index = int.from_bytes(fields[1][-36:-32], "big")
            assert index in (0, 1)
            registration_indices[op].append(index)
            network, round_ = bytes.fromhex(public["network_hex"]), bytes.fromhex(public["round_hex"])
            context = (b"\x01" + len(network).to_bytes(4, "big") + network
                       + bytes.fromhex(public["genesis_hex"] + public["asset_hex"])
                       + len(round_).to_bytes(4, "big") + round_ + bytes([2, index + 1])
                       + (index + 1).to_bytes(4, "big") + bytes([op - 7])
                       + index.to_bytes(4, "big") + bytes.fromhex(facts["digests_hex"][2]))
            assert fields[1] == context
            kind = "input" if op == 8 else "output"
            participant = secrets["participants"][index]
            assert fields[4] == bytes.fromhex(participant[kind + "_credential_r1_hex"])
        if op >= 6 or op in (2, 3):
            assert fields[0] == psets[2]
        if op in (2, 3, 7):
            assert result == [b"OK\x00\x00"]
        if op == 13:
            index = int.from_bytes(fields[1], "big")
            participant = secrets["participants"][index]
            assert fields[2] == bytes.fromhex(participant["receiver_secret_key_hex"])
            assert result[0] == (bytes.fromhex(public["asset_hex"]) + public["outputs"][index]["explicit_value"].to_bytes(8, "big")
                                 + bytes.fromhex(participant["output_asset_bf_hex"] + participant["output_value_bf_hex"]))
        if op in (11, 12):
            assert fields[1:3] == [bytes.fromhex(facts["contexts_hex"][2]), bytes.fromhex(facts["digests_hex"][2])]
    assert registration_indices == {8: [0, 1], 9: [0, 1]}
    for op in manifest["required_ops"]:
        assert op in operations
    sums = "".join(hashlib.sha256(data[name]).hexdigest() + "  " + name + "\n" for name in sorted(ALLOWED - {"SHA256SUMS"}))
    assert data["SHA256SUMS"].decode("ascii") == sums
    return secrets


class PrivateRoundSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_bundle()
        validate_bundle(cls.data)

    def reject_rehashed(self, name, value):
        data = {**self.data, name: value}
        data["SHA256SUMS"] = "".join(hashlib.sha256(data[name]).hexdigest() + "  " + name + "\n"
                                      for name in sorted(ALLOWED - {"SHA256SUMS"})).encode("ascii")
        with self.assertRaises(AssertionError):
            validate_bundle(data)

    def test_exact_schema_and_hashes(self):
        validate_bundle(self.data)

    def test_credential_declarations_bound_to_participant_and_kind(self):
        for index in range(2):
            for kind in ("input", "output"):
                value = json.loads(self.data["secrets.json"])
                value["participants"][index][kind + "_credential_r1_hex"] = "01" * 32
                self.reject_rehashed("secrets.json", json.dumps(value).encode())

    def test_all_entropy_declarations_bound_to_requests(self):
        for index in range(5):
            value = json.loads(self.data["round-facts.json"])
            value["entropy_hex"][index] = "01" * 32
            self.reject_rehashed("round-facts.json", json.dumps(value).encode())

    def test_request_witness_and_entropy_mutations_rejected(self):
        original = frames(self.data["requests.bin"])
        for index, (op, _) in enumerate(original):
            for field in {4: [3], 5: [4], 8: [4, 6], 9: [4, 6], 10: [3]}.get(op, []):
                changed = copy.deepcopy(original)
                changed[index][1][field] = bytes([1]) * 32
                self.reject_frames(changed)

    def test_registration_context_kind_and_participant_mutations_rejected(self):
        original = frames(self.data["requests.bin"])
        for index, (op, _) in enumerate(original):
            if op not in (8, 9):
                continue
            for offset in (-37, -33):
                changed = copy.deepcopy(original)
                context = bytearray(changed[index][1][1])
                context[offset] ^= 1
                changed[index][1][1] = bytes(context)
                self.reject_frames(changed)

    def reject_frames(self, records):
        encoded = bytearray()
        for op, fields in records:
            payload = b"".join(struct.pack(">I", len(field)) + field for field in fields)
            encoded.extend(struct.pack(">IIII", 0x574C434A, 1, op, len(payload)) + payload)
        self.reject_rehashed("requests.bin", bytes(encoded))


def main():
    if sys.argv[1:] == ["--test"]:
        unittest.main(argv=[sys.argv[0]])
        return
    secrets = validate_bundle(load_bundle())
    if sys.argv[1:] == ["--native-participants"]:
        # Private subprocess pipe only; never run this mode in a terminal/log.
        for participant in secrets["participants"]:
            print(" ".join(participant[name] for name in ("receiver_secret_key_hex", "spend_secret_key_hex", "input_asset_bf_hex", "input_value_bf_hex", "output_asset_bf_hex", "output_value_bf_hex")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("private fixture schema rejected")
