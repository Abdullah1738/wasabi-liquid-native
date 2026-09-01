//! Field arithmetic modulo the secp256k1 prime
//! `p = 2^256 - 2^32 - 977`.
//!
//! Since `p ≡ 3 (mod 4)`, every quadratic residue `y2` has the square root
//! `y = y2^((p + 1) / 4) mod p`, and that root is itself a quadratic residue
//! (the "XQuad" root of NBitcoin.Secp256k1's `GE.TryCreateXQuad` and
//! libsecp256k1-zkp's `secp256k1_ge_set_xquad`). These helpers implement the
//! exact root selection the WabiSabi generator derivation and the
//! secp256k1-zkp `Generator`/`PedersenCommitment` encodings are defined over,
//! without any unsafe code or additional dependencies.

/// The secp256k1 field prime `p`, little-endian 64-bit limbs.
const PRIME: [u64; 4] = [
    0xffff_fffe_ffff_fc2f,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// The curve constant `7`, little-endian 64-bit limbs.
pub(crate) const SEVEN: [u64; 4] = [7, 0, 0, 0];

/// Parses a canonical big-endian field element, rejecting values `>= p`.
pub(crate) fn from_be_bytes(bytes: &[u8]) -> Option<[u64; 4]> {
    let array: [u8; 32] = bytes.try_into().ok()?;
    let limbs = bytes_to_limbs(&array);
    if cmp(&limbs, &PRIME) != core::cmp::Ordering::Less {
        return None;
    }
    Some(limbs)
}

/// Returns the least significant bit of the canonical field element.
pub(crate) fn is_odd(a: &[u64; 4]) -> bool {
    a[0] & 1 == 1
}

/// Returns `(a + b) mod p`. Inputs must already be reduced.
pub(crate) fn add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (sum, carry) = adc(a, b);
    // a + b < 2p, so a single conditional subtraction reduces fully. The sum
    // is kept in 5 limbs so the 2^256 carry is never wrapped away.
    let mut wide = [sum[0], sum[1], sum[2], sum[3], carry];
    if carry == 1 || cmp(&sum, &PRIME) != core::cmp::Ordering::Less {
        wide = sub5_prime(wide);
    }
    [wide[0], wide[1], wide[2], wide[3]]
}

/// Returns `a^3 mod p`.
pub(crate) fn cube(a: &[u64; 4]) -> [u64; 4] {
    mul(mul(*a, *a), *a)
}

/// Returns the XQuad square root of `a`: `a^((p + 1) / 4) mod p` when `a` is
/// a quadratic residue (verified by squaring back), or `None` when `a` is a
/// non-residue. The returned root is itself a quadratic residue.
pub(crate) fn sqrt(a: &[u64; 4]) -> Option<[u64; 4]> {
    let root = pow_p_plus_1_quarter(a);
    if mul(root, root) == *a {
        Some(root)
    } else {
        None
    }
}

/// Returns `a^((p + 1) / 4) mod p` by fixed square-and-multiply over the
/// constant exponent `(p + 1) / 4 = 2^254 - 2^30 - 244`.
fn pow_p_plus_1_quarter(a: &[u64; 4]) -> [u64; 4] {
    // (p + 1) / 4 = 2^254 - 2^30 - 244, in little-endian 64-bit limbs.
    const EXPONENT: [u64; 4] = [
        0xffff_ffff_bfff_ff0c,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x3fff_ffff_ffff_ffff,
    ];
    let mut result = [1u64, 0, 0, 0];
    for bit in (0..256).rev() {
        result = mul(result, result);
        if (EXPONENT[bit / 64] >> (bit % 64)) & 1 == 1 {
            result = mul(result, *a);
        }
    }
    result
}

/// Returns `(a * b) mod p` via 256x256-bit schoolbook multiply followed by
/// [`reduce_wide`].
fn mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
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

/// Subtracts `p` from a 5-limb value known to be `>= p`, in two's complement.
fn sub5_prime(mut value: [u64; 5]) -> [u64; 5] {
    let mut borrow = 0i128;
    for i in 0..4 {
        let acc = value[i] as i128 - PRIME[i] as i128 - borrow;
        if acc < 0 {
            value[i] = (acc + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            value[i] = acc as u64;
            borrow = 0;
        }
    }
    value[4] = (value[4] as i128 - borrow) as u64;
    value
}

/// Reduces a 512-bit value modulo `p` by binary long division: process bits
/// from most significant down, maintaining `r = (2r + bit) mod p`. The
/// `2r + bit` step can transiently reach `2p - 1`, so the shift and the
/// conditional subtract use a 5-limb running remainder to avoid truncation.
/// This is the same algorithm as `scalar::reduce_wide`, specialized to `p`.
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
        // if r >= p, subtract p (p fits in the low 4 limbs)
        if cmp5_prime(&r) != core::cmp::Ordering::Less {
            r = sub5_prime(r);
        }
    }
    [r[0], r[1], r[2], r[3]]
}

/// Compares a 5-limb remainder against the field prime.
fn cmp5_prime(r: &[u64; 5]) -> core::cmp::Ordering {
    if r[4] != 0 {
        return core::cmp::Ordering::Greater;
    }
    cmp(&[r[0], r[1], r[2], r[3]], &PRIME)
}

fn get_bit(wide: &[u64; 8], bit: usize) -> bool {
    (wide[bit / 64] >> (bit % 64)) & 1 == 1
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

fn bytes_to_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[32 - 8 * (i + 1)..32 - 8 * i]);
        limbs[i] = u64::from_be_bytes(word);
    }
    limbs
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a 64-char hex string into 32 big-endian bytes, then field limbs.
    fn fe(hex_str: &str) -> [u64; 4] {
        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect();
        from_be_bytes(&bytes).expect("canonical field element")
    }

    fn to_hex(limbs: &[u64; 4]) -> String {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limbs[i].to_be_bytes());
        }
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Independent KATs computed with Python big-int field math (random seed
    // 12345): the expected products and square roots are pinned as byte
    // strings, so these checks do not share any code path with the
    // implementation under test beyond the final comparison.
    #[test]
    fn mul_matches_independent_kats() {
        let cases: [(&str, &str, &str); 4] = [
            (
                "daea58ba4c73a942cd8778e7d340bbcdd1f6f86c029a7245bb91433a6aa79987",
                "5f811cb929645f8b6facaa5090e5e945452ec40a3193ca54ee8971105e503a67",
                "7737bbf8161036d62e90e2031a3d4a6106c1dae89099b957d40a8119d8f60f98",
            ),
            (
                "9c9cea0c2ca1c789a091250e8fe4602442d6cb5c6ed4e94bdfc9e3b11fcff454",
                "87f26aee175f0cd2bb9d58e4f543bbcfbcf74d7a5adad1212fd2b7a48d9fe5b9",
                "73dc53f8a2576c797cf7d16b7fa333a96cd6947a3177b01c3875f357b237c7e7",
            ),
            (
                "34a9af4125ece8452aa4857e8101e89a95c5fb986980a81fbc428d42fa882692",
                "7576714a06057c82527122dc57708107d64a3ce030a1f6d513ed748bb80e3b0d",
                "48e249868c262da00ce59a2e6ed7551b1a9629fdc60a319b63e28a80a7c4292c",
            ),
            (
                "6a5ccc2cbe99854ab0d26ee6fa92890682bde024f7acee2206e0f45856eaa301",
                "94820a06c555663f29ef41d0deea959ea9f559fcf0b3786801b5577d00e266d0",
                "8775aaa6d855273b1a8b2ed9027810c4b5fcfb220f1a0e5c841e460224748006",
            ),
        ];
        for (a, b, product) in cases {
            assert_eq!(
                to_hex(&mul(fe(a), fe(b))),
                product,
                "mul({a}, {b}) mismatch"
            );
        }
    }

    #[test]
    fn sqrt_matches_independent_kats() {
        // Each `a` is a square; the expected root is the unique quadratic-
        // residue (itself-square) root. Odd/even parities are both covered.
        let cases: [(&str, &str); 3] = [
            (
                "ee3b078b5e9d2ebc3c844523c2d1e2c8a2685a4f3042515277b28dd11f192b6a",
                "518eec661d4d7b74e4e4308d95e1332558f31e4ae687313fb6a305afd2355058",
            ),
            (
                "585dd87117596b8799f532f538470850b2f437ecb6d2721ed113b03ab0b329b1",
                "676ca77379f5825e0a3246bec472f1899fffd817436f5913d17f24296c0289f9",
            ),
            (
                "76a1b246a9f4586c911e1a4c9d1f4befadc9afc7933af8f16415b08579d6f076",
                "1eab5cd83b788b660a4de3e4ce9fb6a85473da68d3285151e9c329a8b59a596b",
            ),
        ];
        for (a, root) in cases {
            let computed = sqrt(&fe(a)).expect("a is a quadratic residue");
            assert_eq!(to_hex(&computed), root, "sqrt({a}) mismatch");
            // The returned root must itself be a square (the XQuad rule).
            assert_eq!(mul(computed, computed), fe(a));
        }
    }

    /// Additional reduction vectors from the same independent Python big-int
    /// oracle as the KATs above, re-generated for this corrective pass with a
    /// different random seed (0xC0FFEE) and with boundary operands that stress
    /// the carry/borrow extremes of the bitwise long-division reduction:
    /// `0`, `1`, `2`, `p - 1`, `p - 2`, `p/2`, `(p - 1)/2`, `2^255`,
    /// `2^255 - 1`, `p - 2^32 - 977`, `2^128`, and `2^64 - 1`.
    #[test]
    fn mul_matches_independent_boundary_and_fresh_vectors() {
        const FIELD_MUL_FRESH: [(&str, &str, &str); 8] = [
            (
                "6dbca290a9eab7061f00bca0042db9232c61275c9e6b6cf8950e87d7f5606615",
                "a26b351e6c8042c56814a2bc786a6d2df26fff4cc4fd394d4c10a4fe30cffdda",
                "8617dae4f2adda36ef4152f0273515c2f166301a95c26754b0c1bae5e0c03c8f",
            ),
            (
                "c34bd8e2fe5213e529610ae0eed8f1e7d4c08880a5a4666d54760e7fbc051c6c",
                "194f9545adba52ce4e385994ebac94af6f28d015a2aa0b9d6c50afb6e9fb123d",
                "18d0fb65c40bc866a8a18b34a111eef7668ee8988d97833e146095f2b8b66609",
            ),
            (
                "6df216c33f8f3201d998efd82733e93357de8c051d4b7ef2c675ce05588f882f",
                "607507ebc5b864d733176469aa6ef6308860a84722025e0511dc6f3fcb57d5d8",
                "f870255641407c0940bc90ddb3c94ee62d80801b1fbfad8bbaeef520461b30fd",
            ),
            (
                "b98937dfef0410662de288f12fcb9940da10faaa6fc24b837a2f11088d29b146",
                "81eeadd71198bf1507fdc889fa017ed7c5b790314a2e3224dd4b712ed355871e",
                "49187591f5f4d6ba5e24c84025ba6ac0e8f3b6ca2fc30eaf91c92aaca35646bb",
            ),
            (
                "4763dd191ac44b703371364fc51d1a5eaaabc8d366e0440d3a46305c425a7de1",
                "1167fba4a2927979e5a2a8bef16e981a0b7a6e1d81e4b9e7016590c55646e6d0",
                "a3543704dcb468938bb2767437559b33b0b686ed44c06d12c7d429d3bfbb5438",
            ),
            (
                "9bdb39b2ca3c6a00ee26cbc0358b24d3d27a5f0f5532c8673d01ac0f1b534b87",
                "4307513f1ec1b0b1dee7539c539445f3d6257b492186c8b58de06fbe1a741555",
                "dd62b9ed2b56c7854a23091c24f0e4de673a7d226ff74649d8d7aeb6538e86bd",
            ),
            (
                "64b5e3f81a293b3bd36c78ab3537a844de18f50a43cf423a1d790bcaeffd4d2d",
                "a745fdd552965bcaf177d49f03ddc3bfa88d379db047719de8eef3d67646f8a9",
                "f66d922c86f55a8944cbedd3eee7106f0118d8be8d4f706abf102d29a49b4f4c",
            ),
            (
                "4e52b41980271e94760c9b756320dbe3fce79398852e0400d0b6a46a7048daca",
                "7ad955568f86a26a793ff51bb0baf029520e015e444ed0f2293f65848aa18f43",
                "fee0f7d4e5efef70785c8a761a8f0beb2deb0b638c2f6507121b836d02298e02",
            ),
        ];
        const FIELD_MUL_EDGE: [(&str, &str, &str); 24] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "80000000000000000000000000000000000000000000000000000000000003d1",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000000000000000000000000000000000000000000003",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "0000000000000000000000000000000000000000000000000000000100000b73",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "0000000000000000000000000000000000000000000000000000000000000006",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff85e",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff0bc",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc29",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffc2f",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe16",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffc2f",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe16",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "80000000000000000000000000000000000000000000000000000000000003d1",
                "c00000000000000000000000000000000000000000000000400003d0400ae99c",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000003",
                "80000000000000000000000000000000000000000000000000000001000003d1",
            ),
        ];
        for (a, b, product) in FIELD_MUL_FRESH.iter().chain(FIELD_MUL_EDGE.iter()) {
            assert_eq!(
                to_hex(&mul(fe(a), fe(b))),
                *product,
                "mul({a}, {b}) mismatch"
            );
        }
    }

    #[test]
    fn add_matches_independent_boundary_and_fresh_vectors() {
        const FIELD_ADD_FRESH: [(&str, &str, &str); 6] = [
            (
                "d50ca99e8e59ea07310288290b43dbfbd08e7565d487d3421c720603ec8602d9",
                "9293bf4aed9a76b9e91b8ec1f011e633b7a13dce8e4595df6c24e82c6dbbac73",
                "67a068e97bf460c11a1e16eafb55c22f882fb33462cd69218896ee315a41b31d",
            ),
            (
                "d17dad339930e76e5574e314ddfc20fe1e7c31d38598929675c33f8fcb8031fe",
                "e1660a4195d748358fcd110ce94f47b0a4e307830deef007acfbba2a3f8666ee",
                "b2e3b7752f082fa3e541f421c74b68aec35f39569387829e22bef9bb0b069cbd",
            ),
            (
                "3fe9e76493a8b5d809cea2a86a9218432abb018969cbe6ebd6d91d39227d512d",
                "ff5e243c496a590b748781c961ef7dfce376bd78d7304cb6602f8e87d16bc8be",
                "3f480ba0dd130ee37e562471cc8196400e31bf0240fc33a23708abc1f3e91dbc",
            ),
            (
                "5ab59d10b4a20569e443e6031233f1e03deadc7d1d2e1a2e089934a93d71d058",
                "f9afa64760083c7dad1dd1408b87cfcbf5d46d8127762b7b658141e73ede6f12",
                "5465435814aa41e79161b7439dbbc1ac33bf49fe44a445a96e1a76917c50433b",
            ),
            (
                "34c8a05ca34be96a1c0ae9a87893032bd828056ea86fc09cb7a68aa8611b9b59",
                "3a0806a754f579836e5d9a3007c331a36b7e21f0921082dfc966aed65a10eeaf",
                "6ed0a703f84162ed8a6883d8805634cf43a6275f3a80437c810d397ebb2c8a08",
            ),
            (
                "504516f2106025b5fb65e62582414d3ff0723a8383f43dc40a07a198f7767fd6",
                "5fe2b11364b977561be3ae0c3b97b6c9115600523ea6fb4da0d72f15feb859eb",
                "b027c80575199d0c17499431bdd9040901c83ad5c29b3911aaded0aef62ed9c1",
            ),
        ];
        const FIELD_ADD_EDGE: [(&str, &str, &str); 24] = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000003",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000002",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
            ),
            (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2b",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe16",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe15",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe16",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
            ),
            (
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe15",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
                "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "8000000000000000000000000000000000000000000000000000000000000001",
            ),
            (
                "8000000000000000000000000000000000000000000000000000000000000000",
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
                "7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            ),
        ];
        for (a, b, sum) in FIELD_ADD_FRESH.iter().chain(FIELD_ADD_EDGE.iter()) {
            assert_eq!(to_hex(&add(fe(a), fe(b))), *sum, "add({a}, {b}) mismatch");
        }
    }

    #[test]
    fn mul_is_consistent_with_add_for_small_operands() {
        // Cross-check: a*b for small a equals repeated addition, exercising the
        // reduction against the (independent) add path.
        let three = [3u64, 0, 0, 0];
        let seven = [7u64, 0, 0, 0];
        let mut acc = [0u64; 4];
        for _ in 0..3 {
            acc = add(acc, seven);
        }
        assert_eq!(mul(three, seven), acc);
        assert_eq!(mul(three, seven), [21u64, 0, 0, 0]);
    }
}
