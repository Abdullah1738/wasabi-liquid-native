//! Scalar arithmetic modulo the secp256k1 group order `n`.
//!
//! `Scalar` canonical-checks and stores a 32-byte big-endian value but exposes
//! no arithmetic, and [`SecretKey`] rejects zero. Proof values may legitimately
//! be zero (`v = 0`), so the linear combinations `s = k + c·w (mod n)` are
//! computed here over 64-bit limbs.

/// The secp256k1 group order `n`, little-endian 64-bit limbs.
const ORDER: [u64; 4] = [
    0xbfd2_5e8c_d036_4141,
    0xbaae_dce6_af48_a03b,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
];

/// Parses a canonical big-endian scalar, rejecting values `>= n`.
pub(crate) fn from_be_bytes(bytes: [u8; 32]) -> Option<[u64; 4]> {
    let limbs = bytes_to_limbs(&bytes);
    if cmp(&limbs, &ORDER) != core::cmp::Ordering::Less {
        return None;
    }
    Some(limbs)
}

/// Serializes limbs to a canonical big-endian 32-byte encoding.
pub(crate) fn to_be_bytes(limbs: [u64; 4]) -> [u8; 32] {
    limbs_to_bytes(&limbs)
}

/// Returns `(a + b) mod n`.
pub(crate) fn add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (sum, carry) = adc(a, b);
    // If the addition overflowed or reached/exceeded the order, subtract once.
    if carry == 1 || cmp(&sum, &ORDER) != core::cmp::Ordering::Less {
        sub(sum, ORDER)
    } else {
        sum
    }
}

/// Returns `(a * b) mod n` via 256x256-bit schoolbook multiply followed by
/// bitwise reduction.
pub(crate) fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut wide = [0u64; 8];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &bj) in b.iter().enumerate() {
            let acc = wide[i + j] as u128 + ai as u128 * bj as u128 + carry;
            wide[i + j] = acc as u64;
            carry = acc >> 64;
        }
        let mut k = i + 4;
        while carry != 0 && k < 8 {
            let acc = wide[k] as u128 + carry;
            wide[k] = acc as u64;
            carry = acc >> 64;
            k += 1;
        }
    }
    reduce_wide(wide)
}

/// Reduces a 512-bit value modulo `n` by binary long division: process bits
/// from most significant down, maintaining `r = (2r + bit) mod n`. The
/// `2r + bit` step can transiently reach `2n - 1`, so the shift and the
/// conditional subtract use a 5-limb running remainder to avoid truncation.
fn reduce_wide(wide: [u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 5];
    for bit in (0..512).rev() {
        // r = 2r + bit
        let mut carry = u64::from(get_bit(&wide, bit));
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // if r >= n, subtract n (n fits in the low 4 limbs)
        if cmp5_order(&r) != core::cmp::Ordering::Less {
            sub_order5(&mut r);
        }
    }
    [r[0], r[1], r[2], r[3]]
}

/// Compares a 5-limb remainder against the group order.
fn cmp5_order(r: &[u64; 5]) -> core::cmp::Ordering {
    if r[4] != 0 {
        return core::cmp::Ordering::Greater;
    }
    cmp(&[r[0], r[1], r[2], r[3]], &ORDER)
}

/// Subtracts the group order from a 5-limb remainder known to be `>= n`.
fn sub_order5(r: &mut [u64; 5]) {
    let mut borrow = 0i128;
    for i in 0..4 {
        let acc = r[i] as i128 - ORDER[i] as i128 - borrow;
        if acc < 0 {
            r[i] = (acc + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = acc as u64;
            borrow = 0;
        }
    }
    if borrow != 0 {
        r[4] = r[4].wrapping_sub(1);
    }
}

fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[32 - 8 * (i + 1)..32 - 8 * i]);
        limbs[i] = u64::from_be_bytes(word);
    }
    limbs
}

fn limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limbs[i].to_be_bytes());
    }
    bytes
}

fn cmp(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
    }
    core::cmp::Ordering::Equal
}

fn adc(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let acc = a[i] as u128 + b[i] as u128 + carry;
        out[i] = acc as u64;
        carry = acc >> 64;
    }
    (out, carry as u64)
}

fn sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let acc = a[i] as i128 - b[i] as i128 - borrow;
        if acc < 0 {
            out[i] = (acc + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            out[i] = acc as u64;
            borrow = 0;
        }
    }
    out
}

fn get_bit(wide: &[u64; 8], bit: usize) -> bool {
    (wide[bit / 64] >> (bit % 64)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a 64-char hex string into a canonical scalar, or panics.
    fn sc(hex_str: &str) -> [u64; 4] {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_str[2 * i..2 * i + 2], 16).unwrap();
        }
        from_be_bytes(bytes).expect("canonical scalar")
    }

    fn to_hex(limbs: [u64; 4]) -> String {
        to_be_bytes(limbs)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    // Independent KATs computed with Python big-int scalar math (the same
    // oracle as the field KATs in `field.rs`): expected products and sums are
    // pinned as byte strings, so these checks share no code path with the
    // implementation under test beyond the final comparison. The edge matrices
    // cover `0`, `1`, `2`, `n - 1`, `n - 2`, `n/2`, `(n - 1)/2`, `2^255`,
    // `2^255 - 1`, `2^128`, `2^64 - 1`, and `n - 2^128`.
    #[test]
    fn mul_matches_independent_kats() {
        const SCALAR_MUL_KAT: [(&str, &str, &str); 10] = [
            (
                "d9367405563873a8ade9d6469c97360382020ab29b92d2a88711087103e1a5b0",
                "9f0fa908cf50f980d7f9bd927d6c739384d7bd1183566346801678713231b9be",
                "abca4d625e609091fd155f24547b9f0feee770355841e49221ec96a1f6c08c9a",
            ),
            (
                "3c1aed998b61d059914549a94d3e72ab2d9c0867fda5690d9a3dd3787f478c29",
                "f5fcbe24ae9b156313b2785e0f0c937e9be9994d12e87bc13ab18ee7a2e4bf5f",
                "aa8e7256d9719737d9b15df359996238a869bb587e30270327cfbf6e50132b10",
            ),
            (
                "23971b85de20df8922bda6f4d30907f36c222f0eaaac9d1451170769ede8217c",
                "04d2b4572f97fd48bdffaff30347d84c7a83d0980d2ddde4ca0a2624b4d24691",
                "0a8cedd130c5d926118ec91203ba0bcd59788219eb8ee23e37f16290112bc406",
            ),
            (
                "82a882b2462cf7b38db2033114c5e97d979191e0b0adfca20be076cc5480f135",
                "2351f5f49eaa3cd708b302e48de009fb7f6f72270426ebd85dea1a907b76083f",
                "f98260061d21ed32c139efe3ae06a706d8bf86a5b797b93d04154a5f670e6e8f",
            ),
            (
                "7ed0ba986fd5609173f617ec39baf69408031e9b53e5e1f4b4b1b5fe4ea2a894",
                "08b1558d3dacf081c866f6745dc4f19a52c8bd155730448e619b2fabbf9586b2",
                "331c058922fc7fc64a3cccb717b1c9bcd28faf572cafba9b196a54d2562cb77b",
            ),
            (
                "637e59c42a7c697e2b425d5cae23add5aaf5c189dc3f74f6569eaeee5e452281",
                "68ea7bc00c8f573696f53cf3d4cae2e1c41eaff6ab914b20c15942ce231eb32b",
                "f6d9115f45ea0e402330bb68e39669d0961b0a2a245764cd661348cda3495de0",
            ),
            (
                "b269fd3fa5494deeac0058eb403f44804996335afe73ae3c348eb1bbb7a6d5d7",
                "1724d83cbc72c321c1ab6c3b4b6a62aeb5cba41c706828474c6b01dfe40c382d",
                "a3da35a1954acf7f524d70b8edec975a58c6a73dcf480dbf088974d74f161caa",
            ),
            (
                "9952ada2c9eb4c5d68882c4b9f08e1d976199be7d07081eec9c5da3d448ee61a",
                "cc53e7aa348962d7d3f6e95e0f464dc550f13592592745915c04a739b0616d56",
                "b30bd0999a5e16ba95a7071812e4c42e84c5ae07aa4d03c29f28f715d73cff5c",
            ),
            (
                "916714339c0690e6430e755aba35c6a187e2cab173f39e5fac8e1baca6b6b8ae",
                "41250eb0a5b09dcc949192463678c0e23d2ffc15e2971a90770833895e4ce791",
                "d1e8bf5e1b64af7ca29d0f530a3e3bfb69ddad0ef8f87b6c26c997ea61e6766a",
            ),
            (
                "5fec7c9494a01a0a8f8ab7a27c2cf3b38443a1c01ad435c648f8b2558298279c",
                "c9351a6f88538c80fd693667b1a1de5ab684a19abfe6649e4055eb1e0d836f49",
                "5d49d6e83a185e1ccafc769eaadb8e6fd954f1ac96acfbf1e71c3e34ed581d42",
            ),
        ];
        const SCALAR_MUL_EDGE: [(&str, &str, &str); 24] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "8000000000000000000000000000000000000000000000000000000000012345",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000000000000000000000000000000000000000000003",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "000000000000000000000000000000014551231950b75fc4402da1732fcc0549",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000000000000000000000000000000000000000000006",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "7ffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0351dfc",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "fffffffffffffffffffffffffffffffd755db9cd5e9140777fa4bd19a06a3bf8",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413b",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "3fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681a8efe",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209f",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "3fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681a8efe",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209f",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "7ffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "8000000000000000000000000000000000000000000000000000000000012345",
                "a759c7356071a6f179a5fd7916f3fb026f3eb26d74e800a897ada57a9caad82e",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "800000000000000000000000000000014551231950b75fc4402da1732fc9bebf",
            ),
        ];
        for (a, b, product) in SCALAR_MUL_KAT.iter().chain(SCALAR_MUL_EDGE.iter()) {
            assert_eq!(
                to_hex(mul(sc(a), sc(b))),
                *product,
                "mul({a}, {b}) mismatch"
            );
        }
    }

    #[test]
    fn add_matches_independent_kats() {
        const SCALAR_ADD_KAT: [(&str, &str, &str); 6] = [
            (
                "b3f5486dda9cc9dbbc462f138835eeb5791c54d643356a7163d154d5dfe04732",
                "ca5e23d3b250ff05ece9ca5e3297e14b4587d32bbed501064eca7becff29702b",
                "7e536c418cedc8e1a92ff971bacdd00203f54b1b52c1cb3bf2c972360ed3761c",
            ),
            (
                "4148c876d1004b5664c75c5441a47982f9b2fab2f0caf35f141e0010e0d1cc79",
                "f02aac9ace9dc236871e3551169cf59a1ab90fd1466c117b7a2146c6b07b51f2",
                "317375119f9e0d8cebe591a558416f1e59bd2d9d87ee649ece6ce84ac116dd2a",
            ),
            (
                "8dcff9ed906d027a4ee14cd96b6dc7bd7ef82fcc0a335e1ba0ed90fa6bc2c5bd",
                "baa5278d6b777ab7b19fbf8e57b054c004502113e793cade68affcbed126c5cd",
                "4875217afbe47d3200810c67c31e1c7ec89973f9427e88be49cb2f2c6cb34a49",
            ),
            (
                "d9ed927601db147cd5473f2293d053e672aab117e8bb20196ca300149e65382f",
                "e9c6e00f608dc24bc9fc68af95bd12d906e098441c73a32634d2f960864bfbb7",
                "c3b472856268d6c89f43a7d2298d66c0bedc6c7555e62303e1a39ae8547af2a5",
            ),
            (
                "cdf25f073dc26e33dd753a47c93574ae5cc330ac63d8fcfb14979991e4dfacdd",
                "b9083db5c148de457289a45852112e1f7abc830e81dc414fd7d0d578c1dbb130",
                "86fa9cbcff0b4c794ffedea01b46a2cf1cd0d6d4366c9e0f2c96107dd6851ccc",
            ),
            (
                "86488a2513ad8dddfc28efbf73b66c0a19b521917a12d2ee81cc65959e62d9ad",
                "8a4bc60a3d5df42683d45a166992fcaba4652d0b91de695880cd8bbde18ead2e",
                "1094502f510b82047ffd49d5dd4968b7036b71b65ca89c0b42c792c6afbb459a",
            ),
        ];
        const SCALAR_ADD_EDGE: [(&str, &str, &str); 24] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000003",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413d",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209f",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209e",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209f",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
            ),
            (
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209e",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "8000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
                "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            ),
        ];
        for (a, b, sum) in SCALAR_ADD_KAT.iter().chain(SCALAR_ADD_EDGE.iter()) {
            assert_eq!(to_hex(add(sc(a), sc(b))), *sum, "add({a}, {b}) mismatch");
        }
    }

    #[test]
    fn from_be_bytes_rejects_order_and_above() {
        assert!(from_be_bytes([0u8; 32]).is_some());
        assert!(from_be_bytes(to_be_bytes(ORDER)).is_none());
        assert!(from_be_bytes([0xFFu8; 32]).is_none());
    }
}
