use crate::WalletFactsWireError;

pub(crate) struct Reader<'frame> {
    bytes: &'frame [u8],
    position: usize,
}

impl<'frame> Reader<'frame> {
    pub(crate) const fn new(bytes: &'frame [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    #[cfg(test)]
    pub(crate) const fn at_position(bytes: &'frame [u8], position: usize) -> Self {
        Self { bytes, position }
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'frame [u8], WalletFactsWireError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WalletFactsWireError::LimitExceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(WalletFactsWireError::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, WalletFactsWireError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, WalletFactsWireError> {
        let mut bytes = [0; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, WalletFactsWireError> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, WalletFactsWireError> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn read_array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], WalletFactsWireError> {
        let mut bytes = [0; LENGTH];
        bytes.copy_from_slice(self.take(LENGTH)?);
        Ok(bytes)
    }

    pub(crate) fn require_end(&self) -> Result<(), WalletFactsWireError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(WalletFactsWireError::InvalidEncoding)
        }
    }
}
