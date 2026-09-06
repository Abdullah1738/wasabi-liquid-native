"""Independent stdlib-only loader/schema tests for the opt-in public bundle.

Run after the ignored Rust exporter with WLCJ_PUBLIC_ROUND_FIXTURE_DIR set.
No artifact is written or modified by this loader.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unittest


def keys(value, expected):
    assert isinstance(value, dict) and set(value) == set(expected.split()), "unexpected schema fields"


def unhex(value, size=None):
    assert isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", value)
    data = bytes.fromhex(value)
    assert len(data) <= 1_048_576
    assert size is None or len(data) == size
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, "duplicate JSON key"
        result[key] = value
    return result


def pset_maps(data):
    """Read exact PSET key/value maps, rejecting nonminimal lengths and duplicates."""
    position = 5

    def compact():
        nonlocal position
        assert position < len(data)
        tag = data[position]
        position += 1
        if tag < 253:
            return tag
        width = {253: 2, 254: 4, 255: 8}[tag]
        assert position + width <= len(data)
        value = int.from_bytes(data[position:position + width], "little")
        position += width
        assert value >= {253: 253, 254: 65536, 255: 4294967296}[tag]
        return value

    def take(length):
        nonlocal position
        assert position + length <= len(data)
        value = data[position:position + length]
        position += length
        return value

    maps = []
    while position < len(data):
        fields = {}
        while True:
            length = compact()
            if length == 0:
                break
            key = take(length)
            assert key not in fields
            fields[key] = take(compact())
        maps.append(fields)
    assert len(maps) == 6
    return maps


def pset_public_fields(manifest, data, final):
    maps = pset_maps(data)
    # Exact field allowlists exclude scalars, xpubs, preimages and opaque maps.
    prop = lambda subtype: b"\xfc\x04pset" + bytes([subtype])
    assert set(maps[0]) <= {bytes([n]) for n in (2, 3, 4, 5, 6, 251)} | {prop(1)}
    assert maps[0][b"\x04"] == b"\x02" and maps[0][b"\x05"] == b"\x03"
    for row, fields in zip(manifest["inputs"], maps[1:3]):
        assert set(fields) <= {b"\x01", b"\x0e", b"\x0f", b"\x10", prop(14), prop(19), prop(20)}
        assert fields[b"\x0e"] == unhex(row["txid_wire_hex"])
        assert fields[b"\x0f"] == row["vout"].to_bytes(4, "little")
        assert fields[prop(14)] == unhex(row["rangeproof_hex"])
        assert fields[prop(19)] == unhex(row["asset_hex"])
        assert fields[prop(20)] == unhex(row["asset_proof_hex"])
        script = unhex(row["script_hex"])
        assert fields[b"\x01"] == (unhex(row["asset_commitment_hex"]) + unhex(row["value_commitment_hex"])
                                     + unhex(row["nonce_public_key_hex"]) + bytes([len(script)]) + script)
    for row, fields in zip(manifest["outputs"], maps[3:5]):
        assert set(fields) <= {b"\x03", b"\x04"} | {prop(n) for n in range(1, 11)}
        assert fields[b"\x03"] == row["explicit_value"].to_bytes(8, "little")
        assert fields[b"\x04"] == unhex(row["script_hex"])
        assert fields[prop(2)] == unhex(row["asset_hex"])
        assert fields[prop(6)] == unhex(row["receiver_public_key_hex"])
        assert fields[prop(8)] == row["blinder_index"].to_bytes(4, "little")
        proof_fields = {1: "value_commitment_hex", 3: "asset_commitment_hex", 4: "rangeproof_hex",
                        5: "surjection_proof_hex", 7: "nonce_public_key_hex", 9: "value_proof_hex", 10: "asset_proof_hex"}
        for subtype, name in proof_fields.items():
            if final:
                assert fields[prop(subtype)] == unhex(row[name])
            else:
                assert prop(subtype) not in fields
    assert maps[5] == {b"\x03": manifest["fee"]["explicit_value"].to_bytes(8, "little"),
                       b"\x04": b"", prop(2): unhex(manifest["asset_hex"])}


def validate(manifest, artifacts):
    keys(manifest, "schema limitation profile network_hex genesis_hex round_hex asset_hex fee role_map_hex inputs outputs states files verified_ops assembled_txid_wire_hex assembled_state_digest")
    assert manifest["schema"] == "wlcj-public-round-v1"
    assert manifest["profile"] == 1
    assert "participant-owned" in manifest["limitation"] and "op13" in manifest["limitation"]
    assert "different round" in manifest["limitation"]
    assert manifest["verified_ops"] == list(range(1, 14))
    assert unhex(manifest["network_hex"]) == b"elements-liquid-mainnet"
    assert unhex(manifest["round_hex"]) == b"round-coinjoin-ffi-0001"
    assert unhex(manifest["genesis_hex"], 32) == bytes([0x22]) * 32
    asset = unhex(manifest["asset_hex"], 32)
    unhex(manifest["assembled_txid_wire_hex"], 32)
    assert set(artifacts) == {"preblind.pset", "final.pset"}
    assert len(manifest["files"]) == 2
    assert [f["name"] for f in manifest["files"]] == ["preblind.pset", "final.pset"]
    for file in manifest["files"]:
        keys(file, "name bytes sha256")
        data = artifacts[file["name"]]
        assert 0 < len(data) <= 1_048_576 and len(data) == file["bytes"]
        assert hashlib.sha256(data).hexdigest() == file["sha256"], "artifact hash mismatch"
        assert data.startswith(b"pset\xff")
    keys(manifest["fee"], "index asset_hex explicit_value shares script_hex")
    fee = manifest["fee"]
    assert fee == dict(index=2, asset_hex=asset.hex(), explicit_value=1100, shares=[500, 600], script_hex="")
    assert unhex(manifest["role_map_hex"]) == bytes.fromhex("0000000200000000010000000102")
    assert len(manifest["inputs"]) == len(manifest["outputs"]) == 2
    common = "index role script_hex spend_public_key_hex receiver_public_key_hex asset_hex explicit_value asset_commitment_hex value_commitment_hex nonce_public_key_hex rangeproof_hex surjection_proof_hex asset_proof_hex"
    for index, (input_, output) in enumerate(zip(manifest["inputs"], manifest["outputs"])):
        keys(input_, common + " txid_wire_hex vout")
        keys(output, common + " blinder_index value_proof_hex")
        assert input_["vout"] == output["blinder_index"] == index
        assert unhex(input_["txid_wire_hex"], 32) == bytes([0x30 + index]) * 32
        assert input_["explicit_value"] == [5000, 4000][index]
        assert output["explicit_value"] == input_["explicit_value"] - fee["shares"][index]
        for row in (input_, output):
            assert row["index"] == index and row["role"] == index + 1
            assert unhex(row["asset_hex"], 32) == asset
            for field in ("spend_public_key_hex", "receiver_public_key_hex", "nonce_public_key_hex"):
                assert unhex(row[field], 33)[0] in (2, 3)
            assert unhex(row["asset_commitment_hex"], 33)[0] in (10, 11)
            assert unhex(row["value_commitment_hex"], 33)[0] in (8, 9)
            script = unhex(row["script_hex"], 22)
            pubkey = unhex(row["spend_public_key_hex"])
            assert script == b"\x00\x14" + hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
            for field in ("rangeproof_hex", "surjection_proof_hex", "asset_proof_hex"):
                assert 0 < len(unhex(row[field])) <= 8192
        assert 0 < len(unhex(output["value_proof_hex"])) <= 8192
    assert len(manifest["states"]) == 3
    prior = None
    for index, state in enumerate(manifest["states"]):
        keys(state, "name file context_hex digest phase role ordinal predecessor")
        name = ["preblind", "intermediate", "final"][index]
        assert state["name"] == name
        assert state["file"] == (None if index == 1 else name + ".pset")
        assert state["phase"] == state["ordinal"] == index + 1
        assert state["role"] == (2 if index == 2 else 1)
        assert state["predecessor"] == prior
        unhex(state["digest"], 32)
        network = unhex(manifest["network_hex"])
        round_ = unhex(manifest["round_hex"])
        expected = (b"\x01" + len(network).to_bytes(4, "big") + network
                    + unhex(manifest["genesis_hex"]) + asset + asset
                    + len(round_).to_bytes(4, "big") + round_
                    + bytes([state["phase"], state["role"]]) + state["ordinal"].to_bytes(4, "big")
                    + (b"\x00" if prior is None else b"\x01" + unhex(prior)))
        assert unhex(state["context_hex"]) == expected
        prior = state["digest"]
    assert manifest["assembled_state_digest"] == prior
    pset_public_fields(manifest, artifacts["preblind.pset"], False)
    pset_public_fields(manifest, artifacts["final.pset"], True)


class PublicRoundSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[3]
        directory = Path(os.environ["WLCJ_PUBLIC_ROUND_FIXTURE_DIR"]).resolve(strict=True)
        assert directory.is_relative_to((root / "tmp").resolve()) and directory != root / "tmp"
        assert {p.name for p in directory.iterdir()} == {"manifest.json", "SHA256SUMS", "preblind.pset", "final.pset"}
        data = {}
        for path in directory.iterdir():
            assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 1_048_576
            data[path.name] = path.read_bytes()
        cls.manifest = json.loads(data["manifest.json"], object_pairs_hook=unique_object)
        cls.artifacts = {name: data[name] for name in ("preblind.pset", "final.pset")}
        expected = "".join(hashlib.sha256(data[name]).hexdigest() + "  " + name + "\n"
                           for name in ("preblind.pset", "final.pset", "manifest.json"))
        assert data["SHA256SUMS"].decode("ascii") == expected

    def test_exact_schema_and_hashes(self):
        validate(self.manifest, self.artifacts)

    def test_secret_and_unknown_fields_rejected_at_every_level(self):
        paths = [(), ("fee",), ("inputs", 0), ("outputs", 0), ("states", 0), ("files", 0)]
        for path in paths:
            for name in ("receiver_private_key", "abf", "vbf", "entropy", "credentials", "scalar", "request", "unexpected"):
                mutated = copy.deepcopy(self.manifest)
                target = mutated
                for part in path:
                    target = target[part]
                target[name] = "00" * 32
                with self.assertRaises(AssertionError):
                    validate(mutated, self.artifacts)

    def test_corrupt_truncated_and_swapped_artifacts_rejected(self):
        for name, data in self.artifacts.items():
            for changed in (data[:-1], bytes([data[0] ^ 1]) + data[1:], data + b"\x00"):
                with self.assertRaises(AssertionError):
                    validate(self.manifest, {**self.artifacts, name: changed})
        with self.assertRaises(AssertionError):
            validate(self.manifest, dict(zip(self.artifacts, reversed(list(self.artifacts.values())))))

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(AssertionError):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=unique_object)

    def test_public_metadata_drift_rejected(self):
        for category, field in (("inputs", "rangeproof_hex"), ("outputs", "rangeproof_hex"),
                                ("outputs", "receiver_public_key_hex")):
            mutated = copy.deepcopy(self.manifest)
            original = mutated[category][0][field]
            mutated[category][0][field] = original[:-2] + ("01" if original[-2:] == "00" else "00")
            with self.assertRaises(AssertionError):
                validate(mutated, self.artifacts)

    def test_scalar_and_opaque_pset_fields_rejected_even_with_rehashed_file(self):
        for key in (b"\xfc\x04pset\x00" + bytes([1]) * 32, b"\xfa", b"\x01"):
            name = "preblind.pset"
            original = self.artifacts[name]
            # Insert an extra global pair before the existing pairs. Hashes alone
            # must not authorize a newly introduced scalar/xpub/opaque field.
            data = original[:5] + bytes([len(key)]) + key + b"\x20" + bytes([2]) * 32 + original[5:]
            mutated = copy.deepcopy(self.manifest)
            mutated["files"][0]["bytes"] = len(data)
            mutated["files"][0]["sha256"] = hashlib.sha256(data).hexdigest()
            with self.assertRaises(AssertionError):
                validate(mutated, {**self.artifacts, name: data})


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-records"]:
        PublicRoundSchema.setUpClass()
        validate(PublicRoundSchema.manifest, PublicRoundSchema.artifacts)
        for state in PublicRoundSchema.manifest["states"]:
            if state["file"] is not None:
                print(state["file"], state["context_hex"], state["digest"])
    else:
        unittest.main()
