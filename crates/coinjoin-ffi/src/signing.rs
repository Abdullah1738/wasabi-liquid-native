use super::*;
use collab::{AuthorizedInput, CollabP2wpkhSigner};
use elements::bitcoin::PublicKey;
use elements::{EcdsaSighashType, OutPoint, Txid};
use wasabi_liquid_native_coinjoin_pset_state::MAX_INPUT_COUNT;

fn count(rest: &mut &[u8]) -> Result<usize, Rejection> {
    let count = take_u32(rest)? as usize;
    if count == 0 || count > MAX_INPUT_COUNT {
        return Err(Rejection::ValidationFailed);
    }
    Ok(count)
}

fn public_key(rest: &mut &[u8]) -> Result<PublicKey, Rejection> {
    PublicKey::from_slice(take(rest, 33)?).map_err(|_| Rejection::ValidationFailed)
}

fn authorization(bytes: &[u8]) -> Result<Vec<AuthorizedInput>, Rejection> {
    let mut rest = bytes;
    let count = count(&mut rest)?;
    let mut authorized = Vec::with_capacity(count);
    for index in 0..count {
        // Complete, ascending coverage has exactly these indices.
        if take_u32(&mut rest)? as usize != index {
            return Err(Rejection::ValidationFailed);
        }
        let txid = Txid::from_byte_array(take_array(&mut rest)?);
        let vout = take_u32(&mut rest)?;
        authorized.push(AuthorizedInput {
            index,
            outpoint: OutPoint::new(txid, vout),
            public_key: public_key(&mut rest)?,
        });
    }
    if !rest.is_empty() {
        return Err(Rejection::InvalidFrame);
    }
    Ok(authorized)
}

struct SubmittedSignatures<'a>(Vec<(usize, &'a [u8])>);

impl CollabP2wpkhSigner for SubmittedSignatures<'_> {
    fn sign_digest(
        &mut self,
        index: usize,
        _: &OutPoint,
        _: [u8; 32],
        _: EcdsaSighashType,
    ) -> Option<Vec<u8>> {
        // The existing callback path checks DER, sighash, low-S and the actual
        // native digest/key. No unchecked SignedInputContribution is constructed.
        self.0
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, bytes)| bytes.to_vec())
    }
}

pub(super) fn execute(payload: &[u8], assemble: bool) -> Result<Vec<u8>, Rejection> {
    let fields = expect_fields(payload, &[u32::MAX, u32::MAX, 32, u32::MAX, u32::MAX])?;
    let context = parse_context(fields[1])?;
    let authorized = authorization(fields[3])?;
    let expected = fields[2].try_into().map_err(|_| Rejection::InternalError)?;
    let capability = collab::accept_signing_capability(
        fields[0],
        &context.canonical_context()?,
        expected,
        &authorized,
    )
    .map_err(|_| Rejection::ValidationFailed)?;
    let mut hasher = Sha256::new_with_prefix(b"WLCJ_SIGNING_BINDING_V1");
    for field in &fields[..4] {
        hasher.update((field.len() as u32).to_be_bytes());
        hasher.update(field);
    }
    let binding: [u8; 32] = hasher.finalize().into();
    let mut rest = fields[4];
    let count = count(&mut rest)?;
    let mut response = Vec::new();
    push_field(&mut response, &binding);
    push_field(&mut response, &capability.digest());
    if !assemble {
        let mut owned = Vec::with_capacity(count);
        for _ in 0..count {
            let index = take_u32(&mut rest)? as usize;
            if owned
                .last()
                .is_some_and(|auth: &AuthorizedInput| auth.index >= index)
            {
                return Err(Rejection::ValidationFailed);
            }
            owned.push(*authorized.get(index).ok_or(Rejection::ValidationFailed)?);
        }
        if !rest.is_empty() {
            return Err(Rejection::InvalidFrame);
        }
        let digests = capability
            .owned_digests(&owned)
            .map_err(|_| Rejection::ValidationFailed)?;
        let mut requests = Vec::new();
        push_u32(&mut requests, count as u32);
        for (auth, digest) in owned.iter().zip(digests) {
            push_u32(&mut requests, auth.index as u32);
            requests.extend_from_slice(&auth.outpoint.txid.to_byte_array());
            push_u32(&mut requests, auth.outpoint.vout);
            requests.extend_from_slice(&auth.public_key.to_bytes());
            requests.extend_from_slice(&digest);
            requests.push(0x41);
        }
        push_field(&mut response, &requests);
    } else {
        if count != authorized.len() {
            return Err(Rejection::VerificationFailed);
        }
        let mut submitted = SubmittedSignatures(Vec::with_capacity(count));
        let mut seen = vec![false; authorized.len()];
        for _ in 0..count {
            let contribution_binding: [u8; 32] = take_array(&mut rest)?;
            let index = take_u32(&mut rest)? as usize;
            let key = PublicKey::from_slice(take(&mut rest, 33)?)
                .map_err(|_| Rejection::VerificationFailed)?;
            let length = take_u32(&mut rest)? as usize;
            let signature = take(&mut rest, length)?;
            let auth = authorized.get(index).ok_or(Rejection::VerificationFailed)?;
            if contribution_binding != binding
                || seen[index]
                || key != auth.public_key
                || length > 73
            {
                return Err(Rejection::VerificationFailed);
            }
            seen[index] = true;
            submitted.0.push((index, signature));
        }
        if !rest.is_empty() {
            return Err(Rejection::InvalidFrame);
        }
        let contributions = collab::sign_owned_inputs(&capability, &authorized, &mut submitted)
            .map_err(|_| Rejection::VerificationFailed)?;
        let finalized = collab::assemble_signatures(&capability, &contributions)
            .map_err(|_| Rejection::VerificationFailed)?;
        push_field(&mut response, &serialize(finalized.transaction()));
        push_field(&mut response, &finalized.txid().to_byte_array());
    }
    Ok(response)
}
