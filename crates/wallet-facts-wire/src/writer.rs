use crate::WalletFactsWireError;
use zeroize::Zeroize;

pub(crate) struct Writer {
    bytes: Vec<u8>,
    expected_length: usize,
    valid: bool,
}

impl Writer {
    pub(crate) fn new(expected_length: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(expected_length),
            expected_length,
            valid: true,
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) {
        let Some(end) = self.bytes.len().checked_add(bytes.len()) else {
            self.valid = false;
            return;
        };
        if end > self.expected_length {
            self.valid = false;
            return;
        }
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn write_u8(&mut self, value: u8) {
        self.write(&[value]);
    }

    pub(crate) fn write_u16(&mut self, value: u16) {
        self.write(&value.to_le_bytes());
    }

    pub(crate) fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    pub(crate) fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    pub(crate) fn finish(mut self) -> Result<Vec<u8>, WalletFactsWireError> {
        if self.valid && self.bytes.len() == self.expected_length {
            Ok(core::mem::take(&mut self.bytes))
        } else {
            Err(WalletFactsWireError::InvalidEncoding)
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        crate::note_drop(
            crate::DropKind::Writer,
            self.bytes.iter().all(|byte| *byte == 0),
        );
    }
}

pub(crate) fn checked_add(left: usize, right: usize) -> Result<usize, WalletFactsWireError> {
    left.checked_add(right)
        .ok_or(WalletFactsWireError::LimitExceeded)
}

pub(crate) fn checked_multiply(left: usize, right: usize) -> Result<usize, WalletFactsWireError> {
    left.checked_mul(right)
        .ok_or(WalletFactsWireError::LimitExceeded)
}
