#![allow(unused_doc_comments, missing_docs)]
use crate::accumulator::{
    generate_fr, pair, schnorr, Accumulator, Element, MembershipWitness, Polynomial, PublicKey, SecretKey, SALT,
};
use crate::utils::{g1, sc, AccParams, PublicKeys, UserID};
use ffi_support::{ ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError, HandleError, Handle};
use blsful::inner_types::*;
use lazy_static::lazy_static;
use std::{ptr, slice, string::String, vec::Vec};
use std::os::raw::c_void;
use std::str::from_utf8;
use std::panic::{self, AssertUnwindSafe};

use super::{servers::Server, utils::*, witness::*};

lazy_static! {
    pub static ref SERVERS: ConcurrentHandleMap<Server> = ConcurrentHandleMap::new();
}

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

// To convert from JSON to Rust types
macro_rules! from_bytes {
    ($func_name:ident, $type:ty) => {
        fn $func_name(byte_array: ByteArray) -> Option<$type> {
            // Convert the raw bytes to a &str, must bye utf-8
            let json_str = match unsafe { from_utf8(std::slice::from_raw_parts(byte_array.data, byte_array.length)) } {
                Ok(str) => str,
                Err(_) => return None,
            };

            // Deserialize the JSON string to the specified type
            serde_json::from_str::<$type>(json_str).ok()
        }
    };
}

from_bytes!(user_id_from_bytes, UserID);
from_bytes!(acc_params_from_bytes, AccParams);
from_bytes!(element_from_bytes, Element);
from_bytes!(g1_from_bytes, G1Projective);
from_bytes!(usize_from_bytes, usize);
from_bytes!(scalar_list_from_bytes, Vec<Scalar>);

#[no_mangle]
pub extern "C" fn allosaurus_new_server(err: &mut ExternError) -> u64 {
    SERVERS.insert_with_output(err, || Server::new(&AccParams::default()))
}

#[no_mangle]
pub extern "C" fn allosaurus_server_add(handle: u64, user_id: ByteArray, witness: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let user_id_result = user_id_from_bytes(user_id).unwrap();
    SERVERS.call_with_result_mut(err, handle, |server| {
        let witness_data = server.add(user_id_result).ok_or(ExternError::new_error(ErrorCode::new(-2), "unable to add user_id".to_string()))?;
        let json_string = serde_json::to_string(&witness_data)?;
        *witness = ByteBuffer::from_vec(json_string.into_bytes());
        Ok(())
    });
    err.get_code().code()
}

// #[no_mangle]
// pub extern "C" fn allosaurus_server_delete(
//     handle: u64,
//     user_id: ByteArray, 
//     acc_buffer: &mut ByteBuffer,
//     err: &mut ExternError,
// ) -> i32 {
//     let user_id_result = user_id_from_bytes(user_id).unwrap();
//     SERVERS.call_with_result_mut(err, handle, move |server| {
//         let acc = server.delete(user_id_result).ok_or(ExternError::new_error(ErrorCode::new(-2), "unable to delete user_id".to_string()))?;
//         let json_string = serde_json::to_string(&acc)?;
//         *acc_buffer = ByteBuffer::from_vec(json_string.into_bytes());
//         Ok(())
//     });
//     err.get_code().code()
// }

// #[no_mangle]
// pub extern "C" fn allosaurus_server_witness(
//     handle: u64,
//     params: ByteArray,
//     user_id: ByteArray,
//     challenge: ByteArray,
//     response: ByteArray,
//     user_pub_key: ByteArray,
//     witness_buffer: &mut ByteBuffer,
//     acc_buffer: &mut ByteBuffer,
//     err: &mut ExternError,
// ) -> i32 {
//     let acc_param = acc_params_from_bytes(params).unwrap();
//     let user_id = user_id_from_bytes(user_id).unwrap();
//     let challenge = element_from_bytes(challenge).unwrap();
//     let response = element_from_bytes(response).unwrap();
//     let user_pub_key = g1_from_bytes(user_pub_key).unwrap();

//     SERVERS.call_with_result_mut(err, handle, move |server| {
//         let (witness, acc) = server.witness(&acc_param, &user_id, &challenge, &response, &user_pub_key).ok_or(ExternError::new_error(ErrorCode::new(-2), "unable to witness".to_string()))?;
//         let json_string_witness = serde_json::to_string(&witness)?;
//         let json_string_acc = serde_json::to_string(&acc)?;
//         *witness_buffer = ByteBuffer::from_vec(json_string_witness.into_bytes());
//         *acc_buffer = ByteBuffer::from_vec(json_string_acc.into_bytes());
//         Ok(())
//     });

//     err.get_code().code()
// }

// #[no_mangle]
// pub extern "C" fn allosaurus_server_update(
//     handle: u64,
//     num_epochs: ByteArray,
//     y_shares: ByteArray,
//     ds_buffer: &mut ByteBuffer,
//     vs_buffer: &mut ByteBuffer,
//     err: &mut ExternError,
// ) -> i32 {
//     let num_epochs = usize_from_bytes(num_epochs).unwrap();
//     let y_shares_slice = scalar_list_from_bytes(y_shares).unwrap();

//     SERVERS.call_with_result_mut(err, handle, move |server| {
//         let (ds, vs) = server.update(num_epochs, &y_shares_slice);
//         let json_string_ds = serde_json::to_string(&ds)?;
//         let json_string_vs = serde_json::to_string(&vs)?;
//         *ds_buffer = ByteBuffer::from_vec(json_string_ds.into_bytes());
//         *vs_buffer = ByteBuffer::from_vec(json_string_vs.into_bytes());
//         Ok(())
//     });

//     err.get_code().code()
// }

// #[no_mangle]
// pub extern "C" fn allosaurus_get_epoch(handle: u64, epoch: &mut ByteBuffer, err: &mut ExternError) -> i32 {
//     SERVERS.call_with_result_mut(err, handle, |server| {
//         let epoch_data = server.get_epoch();
//         let json_string = serde_json::to_string(&epoch_data)?;
//         *epoch = ByteBuffer::from_vec(json_string.into_bytes());
//         Ok(())
//     });
//     err.get_code().code()
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allosaurus_new_server() {
        let mut err = ExternError::default();
        let server_handle = allosaurus_new_server(&mut err);

        assert_eq!(err.get_code(), ErrorCode::SUCCESS);

        let handle = Handle::from_u64(server_handle).expect("Invalid handle");
        let server_exists = SERVERS.get(handle, |_server| {
            Ok::<bool, HandleError>(true)
        }).unwrap_or(false);
        assert!(server_exists, "Server should exist in the map after creation");

        SERVERS.remove(handle).expect("Failed to remove server");
    }

}