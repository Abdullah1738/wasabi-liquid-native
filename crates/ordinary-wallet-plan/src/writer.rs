use zeroize::Zeroize;

use crate::OrdinaryWalletPlanWireError;

struct ScopedBytes<const LENGTH: usize>([u8; LENGTH]);

struct ScopedU16(u16);

impl Drop for ScopedU16 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ScopedU32(u32);

impl Drop for ScopedU32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ScopedU64(u64);

impl Drop for ScopedU64 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct ScopedUsize(usize);

impl Drop for ScopedUsize {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const LENGTH: usize> Drop for ScopedBytes<LENGTH> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) struct Writer {
    bytes: Vec<u8>,
    expected_length: usize,
    valid: bool,
}

impl Writer {
    pub(crate) fn new(mut expected_length: usize) -> Self {
        let mut expected = ScopedUsize(expected_length);
        expected_length.zeroize();
        Self {
            bytes: Vec::with_capacity(expected.0),
            expected_length: core::mem::take(&mut expected.0),
            valid: true,
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) {
        let Some(end) = self.bytes.len().checked_add(bytes.len()) else {
            self.valid = false;
            return;
        };
        let end = ScopedUsize(end);
        if end.0 > self.expected_length {
            self.valid = false;
            return;
        }
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn write_u16(&mut self, value: u16) {
        let value = ScopedU16(value);
        let bytes = ScopedBytes(value.0.to_le_bytes());
        self.write(&bytes.0);
    }

    pub(crate) fn write_u32(&mut self, value: u32) {
        let value = ScopedU32(value);
        let bytes = ScopedBytes(value.0.to_le_bytes());
        self.write(&bytes.0);
    }

    pub(crate) fn write_u64(&mut self, value: u64) {
        let value = ScopedU64(value);
        let bytes = ScopedBytes(value.0.to_le_bytes());
        self.write(&bytes.0);
    }

    pub(crate) fn finish(mut self) -> Result<Vec<u8>, OrdinaryWalletPlanWireError> {
        if self.valid && self.bytes.len() == self.expected_length {
            #[cfg(test)]
            crate::maybe_panic_at(crate::StagingPoint::WriterTransfer);
            Ok(core::mem::take(&mut self.bytes))
        } else {
            Err(OrdinaryWalletPlanWireError::InvalidEncoding)
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.expected_length.zeroize();
        self.valid = false;
        #[cfg(test)]
        crate::note_zeroized_drop(
            crate::DropKind::Writer,
            self.bytes.iter().all(|byte| *byte == 0) && self.expected_length == 0 && !self.valid,
        );
    }
}
