// dual_byte_buffer.rs
use ffi_support::{ByteBuffer, FfiStr, ExternError, IntoFfi};

// custom bytebuffer that support two bytebuffers
pub struct DualByteBuffer {
    pub buffer1: ByteBuffer,
    pub buffer2: ByteBuffer,
}

pub trait ByteBufferHandler {
    fn new(buffer1_size: usize, buffer2_size: usize) -> Self;
    fn set_buffer1(&mut self, data: Vec<u8>);
    fn set_buffer2(&mut self, data: Vec<u8>);
    fn to_vec(&self) -> Vec<u8>;
    fn from_vec(buffer: Vec<u8>) -> Self;
}

unsafe impl IntoFfi for &mut DualByteBuffer {
    type Value = (*mut ByteBuffer, *mut ByteBuffer);

    fn into_ffi_value(self) -> Self::Value {
        (&mut self.buffer1, &mut self.buffer2)
    }

    fn ffi_default() -> Self::Value {
        (std::ptr::null_mut(), std::ptr::null_mut())
    }
}



impl ByteBufferHandler for DualByteBuffer {
    fn new(buffer1_size: usize, buffer2_size: usize) -> Self {
        DualByteBuffer {
            buffer1: ByteBuffer::new_with_size(buffer1_size),
            buffer2: ByteBuffer::new_with_size(buffer2_size),
        }
    }

    fn set_buffer1(&mut self, data: Vec<u8>) {
        self.buffer1 = ByteBuffer::from_vec(data);
    }

    fn set_buffer2(&mut self, data: Vec<u8>) {
        self.buffer2 = ByteBuffer::from_vec(data);
    }

    /// Converts the DualByteBuffer to a vector, with each buffer's length as a prefix.
    fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();

        let buffer1_bytes = self.buffer1.as_slice();
        let buffer2_bytes = self.buffer2.as_slice();

        result.extend((buffer1_bytes.len() as u32).to_ne_bytes());
        result.extend((buffer2_bytes.len() as u32).to_ne_bytes());

        result.extend(buffer1_bytes);
        result.extend(buffer2_bytes);

        result
    }

    /// Creates a DualByteBuffer from a vector, expecting two length prefixes.
    fn from_vec(buffer: Vec<u8>) -> Self {
        let buffer1_len = u32::from_ne_bytes(buffer[0..4].try_into().unwrap()) as usize;
        let buffer2_len = u32::from_ne_bytes(buffer[4..8].try_into().unwrap()) as usize;

        let buffer1 = ByteBuffer::from_vec(buffer[8..8 + buffer1_len].to_vec());
        let buffer2 = ByteBuffer::from_vec(buffer[8 + buffer1_len..8 + buffer1_len + buffer2_len].to_vec());

        DualByteBuffer {
            buffer1,
            buffer2,
        }
    }
}
