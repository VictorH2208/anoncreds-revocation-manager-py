#![allow(unused_doc_comments, missing_docs)]
use crate::accumulator::{
    generate_fr, pair, schnorr, Accumulator, Element, MembershipWitness, Polynomial, PublicKey, SecretKey, SALT,
};
use crate::utils::{g1, sc, AccParams, PublicKeys, UserID};
use ffi_support::{
    define_bytebuffer_destructor, define_handle_map_deleter, define_string_destructor, ByteBuffer,
    ConcurrentHandleMap, ErrorCode, ExternError,
};
use blsful::inner_types::*;
use lazy_static::lazy_static;
use std::{ptr, slice, string::String, vec::Vec};
use std::os::raw::c_void;

use super::{servers::Server, utils::*, witness::*};

/// Used for receiving byte arrays
#[repr(C)]
pub struct ByteArray {
    length: usize,
    data: *const u8,
}

impl Default for ByteArray {
    fn default() -> Self {
        Self {
            length: 0,
            data: ptr::null(),
        }
    }
}

impl From<&Vec<u8>> for ByteArray {
    fn from(b: &Vec<u8>) -> Self {
        Self::from_slice(b.as_slice())
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(b: Vec<u8>) -> Self {
        Self::from_slice(b.as_slice())
    }
}

impl From<ByteBuffer> for ByteArray {
    fn from(b: ByteBuffer) -> Self {
        Self::from_slice(&b.destroy_into_vec())
    }
}

impl ByteArray {
    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() || self.length == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(self.data, self.length).to_vec() }
        }
    }

    /// Convert to a byte vector if possible
    /// Some if success
    /// None if failure
    pub fn to_opt_vec(&self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            None
        } else if self.length == 0 {
            Some(Vec::new())
        } else {
            Some(unsafe { slice::from_raw_parts(self.data, self.length).to_vec() })
        }
    }

    /// Convert to outgoing ByteBuffer
    pub fn into_byte_buffer(self) -> ByteBuffer {
        ByteBuffer::from_vec(self.to_vec())
    }

    /// Convert from a slice
    pub fn from_slice<I: AsRef<[u8]>>(data: I) -> Self {
        let data = data.as_ref();
        Self {
            length: data.len(),
            data: data.as_ptr(),
        }
    }
}

macro_rules! from_byte_array {
    ($func_name:ident, $type:ty) => {
        fn $func_name(byte_array: ByteArray) -> Option<$type> {
            use std::slice;
            use serde::Deserialize;
            use bincode;

            // Ensure that the pointer is not null and the length is positive
            if byte_array.data.is_null() || byte_array.length == 0 {
                None
            } else {
                // Convert ByteArray to slice of u8
                let data_slice = unsafe {
                    slice::from_raw_parts(byte_array.data, byte_array.length)
                };

                // Deserialize data to the specified type
                bincode::deserialize::<$type>(data_slice).ok()
            }
        }
    };
}

from_byte_array!(acc_params_from_bytes, AccParams);
from_byte_array!(user_id_from_bytes, UserID);
from_byte_array!(challenge_from_bytes, Element);
from_byte_array!(response_from_bytes, Element);
from_byte_array!(public_keys_from_bytes, G1Projective);
from_byte_array!(num_epochs_from_bytes, usize);

#[no_mangle]
pub extern "C" fn allosaurus_new_server() -> *mut c_void {
    let params = AccParams::default();
    let server = Server::new(&params);
    Box::into_raw(Box::new(server)) as *mut c_void
}

#[no_mangle]
pub extern "C" fn allosaurus_server_add(server_ptr: *mut c_void, user_id: ByteArray, witness: &mut ByteBuffer) -> i32 {
    if server_ptr.is_null() {
        return -1;
    }
    let server = unsafe { &mut *(server_ptr as *mut Server) };
    let user_id = user_id_from_bytes(user_id).unwrap();

    match server.add(user_id) {
        Some(witness_data) => {
            let serialized_witness = match bincode::serialize(&witness_data) {
                Ok(data) => data,
                Err(_) => return -2,
            };

            let witness_buffer = ByteBuffer::from_vec(serialized_witness);
            *witness = witness_buffer;
            0
        },
        None => -3,
    }
}

#[no_mangle]
pub extern "C" fn allosaurus_server_delete(
    server_ptr: *mut c_void, 
    user_id: ByteArray, 
    acc_buffer: &mut ByteBuffer
) -> i32 {
    if server_ptr.is_null() {
        return -1;
    }
    let server = unsafe { &mut *(server_ptr as *mut Server) }; 
    let user_id = user_id_from_bytes(user_id).unwrap();

    match server.delete(user_id) {
        Some(acc) => {
            let serialized_acc = match bincode::serialize(&acc) {
                Ok(data) => data,
                Err(_) => return -2,
            };

            *acc_buffer = ByteBuffer::from_vec(serialized_acc);
            0
        },
        None => -3,
    }
}

#[no_mangle]
pub extern "C" fn allosaurus_server_witness(
    server_ptr: *mut c_void, 
    params: ByteArray,
    user_id: ByteArray, 
    challenge: ByteArray,
    response: ByteArray,
    user_pub_key: ByteArray,
    witness_buffer: &mut ByteBuffer,
    acc_buffer: &mut ByteBuffer
) -> i32 {
    if server_ptr.is_null() {
        return -1;
    }
    let server = unsafe { &mut *(server_ptr as *mut Server) };
    let acc_param = acc_params_from_bytes(params).unwrap();
    let user_id = user_id_from_bytes(user_id).unwrap();
    let challenge = challenge_from_bytes(challenge).unwrap();
    let response = response_from_bytes(response).unwrap();
    let user_pub_key = public_keys_from_bytes(user_pub_key).unwrap();

    match server.witness(&acc_param, &user_id, &challenge, &response, &user_pub_key) {
        Some((witness_data, acc_data)) => {
            let serialized_witness = match bincode::serialize(&witness_data) {
                Ok(data) => data,
                Err(_) => return -2,
            };
            let serialized_acc = match bincode::serialize(&acc_data) {
                Ok(data) => data,
                Err(_) => return -3,
            };

            *witness_buffer = ByteBuffer::from_vec(serialized_witness);
            *acc_buffer = ByteBuffer::from_vec(serialized_acc);
            0
        },
        None => -4,
    }
}

#[no_mangle]
pub extern "C" fn allosaurus_server_update(
    server_ptr: *mut c_void,
    num_epochs: ByteArray,
    y_shares: *const Scalar,
    y_shares_len: usize,
    ds_buffer: &mut ByteBuffer,
    vs_buffer: &mut ByteBuffer
) -> i32 {
    if server_ptr.is_null() {
        return -1;
    }
    let server = unsafe { &mut *(server_ptr as *mut Server) };
    let num_epochs = num_epochs_from_bytes(num_epochs).unwrap();
    let y_shares_slice = unsafe { std::slice::from_raw_parts(y_shares, y_shares_len) };

    let (ds, vs) = server.update(num_epochs, y_shares_slice);
    let serialized_ds = match bincode::serialize(&ds) {
        Ok(data) => data,
        Err(_) => return -2,
    };
    let serialized_vs = match bincode::serialize(&vs) {
        Ok(data) => data,
        Err(_) => return -3,
    };

    *ds_buffer = ByteBuffer::from_vec(serialized_ds);
    *vs_buffer = ByteBuffer::from_vec(serialized_vs);

    0 
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::allosaurus_new_server;
    use std::ptr;

    #[test]
    fn test_allosaurus_new_server_with_default_params() {
        unsafe {
            let server_ptr = allosaurus_new_server();
            assert!(!server_ptr.is_null(), "Server should not be null");
        }
    }

    #[test]
    fn test_allosaurus_server_add() {
        unsafe {
            let server_ptr = allosaurus_new_server();
            assert!(!server_ptr.is_null(), "Server pointer should not be null");

            let user_id = UserID::random();
            let user_id_bytes = bincode::serialize(&user_id).unwrap();
            let user_id_ba = ByteArray {
                length: user_id_bytes.len(),
                data: user_id_bytes.as_ptr(),
            };

            let witness_vec = vec![0u8; 1024]; 
            let mut witness_buffer = ByteBuffer::from_vec(witness_vec);

            let result = allosaurus_server_add(server_ptr, user_id_ba, &mut witness_buffer);
            assert_eq!(result, 0, "Expected success result from server add");
        }
    }

    #[test]
    fn test_allosaurus_server_delete() {
        unsafe {
            let server_ptr = allosaurus_new_server();
            assert!(!server_ptr.is_null(), "Server pointer should not be null");

            let user_id = UserID::random();
            let user_id_bytes = bincode::serialize(&user_id).unwrap();
            let user_id_ba = ByteArray {
                length: user_id_bytes.len(),
                data: user_id_bytes.as_ptr(),
            };
            let user_id_ba_1 = ByteArray {
                length: user_id_bytes.len(),
                data: user_id_bytes.as_ptr(),
            };

            let witness_vec = vec![0u8; 1024];
            let mut witness_buffer = ByteBuffer::from_vec(witness_vec); 
            let acc_vec = vec![0u8; 1024];
            let mut acc_buffer = ByteBuffer::from_vec(acc_vec);

            let result = allosaurus_server_add(server_ptr, user_id_ba, &mut witness_buffer);
            assert_eq!(result, 0, "Expected success result from server add");

            let result = allosaurus_server_delete(server_ptr, user_id_ba_1, &mut acc_buffer);
            assert_eq!(result, 0, "Expected success result from server delete");
        }
    }

}