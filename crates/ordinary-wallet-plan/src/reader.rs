use crate::OrdinaryWalletPlanWireError;
use zeroize::Zeroize;

struct ScopedBytes<const LENGTH: usize>([u8; LENGTH]);

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

pub(crate) struct Reader<'frame> {
    bytes: &'frame [u8],
    position: usize,
}

impl<'frame> Reader<'frame> {
    pub(crate) const fn new(bytes: &'frame [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) fn take(
        &mut self,
        mut length: usize,
    ) -> Result<&'frame [u8], OrdinaryWalletPlanWireError> {
        let length_value = ScopedUsize(length);
        length.zeroize();
        let mut end = ScopedUsize(
            self.position
                .checked_add(length_value.0)
                .ok_or(OrdinaryWalletPlanWireError::LimitExceeded)?,
        );
        let value = self
            .bytes
            .get(self.position..end.0)
            .ok_or(OrdinaryWalletPlanWireError::InvalidEncoding)?;
        self.position = core::mem::take(&mut end.0);
        Ok(value)
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, OrdinaryWalletPlanWireError> {
        let mut bytes = ScopedBytes([0; 2]);
        bytes.0.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes.0))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, OrdinaryWalletPlanWireError> {
        let mut bytes = ScopedBytes([0; 4]);
        bytes.0.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes.0))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, OrdinaryWalletPlanWireError> {
        let mut bytes = ScopedBytes([0; 8]);
        bytes.0.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes.0))
    }

    pub(crate) fn read_array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], OrdinaryWalletPlanWireError> {
        let mut bytes = ScopedBytes([0; LENGTH]);
        bytes.0.copy_from_slice(self.take(LENGTH)?);
        Ok(bytes.0)
    }

    pub(crate) fn require_end(&self) -> Result<(), OrdinaryWalletPlanWireError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(OrdinaryWalletPlanWireError::InvalidEncoding)
        }
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        self.position.zeroize();
    }
}
