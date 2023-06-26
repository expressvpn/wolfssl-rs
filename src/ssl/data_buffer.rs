use bytes::{Buf, BytesMut};

/// A thin wrapper around [`BytesMut`] whose role is to simplify operations that
/// the WolfSSL Custom IO callbacks would require.
#[derive(Debug)]
pub struct DataBuffer(BytesMut);

impl DataBuffer {
    /// Constructs a [`Self`] with capacity `sz`
    pub fn with_capacity(sz: usize) -> Self {
        Self(BytesMut::with_capacity(sz))
    }
}

impl std::ops::Deref for DataBuffer {
    type Target = BytesMut;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for DataBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Buf for DataBuffer {
    fn advance(&mut self, cnt: usize) {
        self.0.advance(cnt)
    }

    fn chunk(&self) -> &[u8] {
        self.0.chunk()
    }

    fn remaining(&self) -> usize {
        self.0.remaining()
    }
}
