#![allow(unused_doc_comments, missing_docs)]
use crate::accumulator::{Accumulator, SecretKey,};
use crate::utils::{AccParams, PublicKeys, UserID};
use ffi_support::{
    define_bytebuffer_destructor, define_handle_map_deleter, define_string_destructor, ByteBuffer,
    ConcurrentHandleMap, ErrorCode, ExternError,HandleError, Handle
};
use blsful::inner_types::*;
use lazy_static::lazy_static;
use std::{ptr, slice, vec::Vec};
use postcard;
use crate::custom_bytebuffer::CustomStructForServerUpdate;
use super::{servers::Server, witness::*, user::*};

lazy_static! {
    pub static ref SERVERS: ConcurrentHandleMap<Server> = ConcurrentHandleMap::new();
}

/// Cleanup created strings
define_string_destructor!(allosaurus_string_free);
/// Cleanup created byte buffers
define_bytebuffer_destructor!(allosaurus_byte_buffer_free);
/// Cleanup created proof contexts
define_handle_map_deleter!(SERVERS, allosaurus_create_proof_free);

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

    /// Convert to a slice
    pub fn to_fixed_array(&self) -> Option<[u8; 32]> {
        if self.length == 32 && !self.data.is_null() {
            // Safe because we've checked that data is not null and length is exactly 32
            unsafe {
                let slice = slice::from_raw_parts(self.data, self.length);
                let array: [u8; 32] = slice.try_into().expect("Slice with correct length");
                Some(array)
            }
        } else {
            None
        }
    }
}

macro_rules! from_bytes {
    ($name:ident, $type:ty) => {
        fn $name(input: Vec<u8>) -> Option<$type> {
            if input.len() != <$type>::BYTES {
                return None;
            }

            match <[u8; <$type>::BYTES]>::try_from(input.as_slice()) {
                Ok(bytes) => <$type>::from_bytes(bytes),
                Err(_) => None,
            }
        }
    };
}

// from_bytes!(element_from_bytes, Element);
// from_bytes!(acc_params_from_bytes, AccParams);

#[no_mangle]
pub extern "C" fn allosaurus_new_server(err: &mut ExternError) -> u64 {
    SERVERS.insert_with_output(err, || Server::new(&AccParams::default()))
}

#[no_mangle]
pub extern "C" fn allosaurus_new_user(handle: u64, user: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let handle = Handle::from_u64(handle).unwrap();
    let result = SERVERS.get(handle, |server| {
        let new_user = User::new(server, UserID::random());
        let serialized_user = postcard::to_stdvec(&new_user).unwrap();
        *user = ByteBuffer::from_vec(serialized_user);
        Ok::<(), HandleError>(())
    });
    match result {
        Ok(_) => 0,
        Err(_) => {
            *err = ExternError::new_error(ErrorCode::new(-2), "unable to get add new user".to_string());
            -1
        }
    };
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_add(handle: u64, user: ByteArray, witness_buffer: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let deserial_user: User = postcard::from_bytes(&user.to_vec()).unwrap();
    let user_id = deserial_user.get_id();
    let result = SERVERS.call_with_result_mut(err, handle, move |server| {
        server.add(user_id).map_or_else(
            || Err(ExternError::new_error(ErrorCode::new(-2), "unable to add user".to_string())),
            |witness| Ok(ByteBuffer::from_vec(postcard::to_stdvec(&witness).unwrap()))
        )
    });
    if err.get_code().is_success() {
        *witness_buffer = result;
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_delete(handle: u64, user: ByteArray, acc_buffer: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let deserial_user: User = postcard::from_bytes(&user.to_vec()).unwrap();
    let user_id = deserial_user.get_id();
    let result = SERVERS.call_with_result_mut(err, handle, move |server| {
        server.delete(user_id).map_or_else(
            || Err(ExternError::new_error(ErrorCode::new(-2), "unable to delete user_id".to_string())),
            |acc| Ok(ByteBuffer::from_vec(postcard::to_stdvec(&acc).unwrap()))
        )
    });
    if err.get_code().is_success() {
        *acc_buffer = result;
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_update(
    handle: u64,
    num_epochs: u64,
    y_shares: ByteArray,
    result_buffer: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let y_shares: Vec<Scalar> = postcard::from_bytes(&y_shares.to_vec()).unwrap();
    let result = SERVERS.call_with_output_mut(err, handle, move |server| {
        let (ds, vs) = server.update(num_epochs.try_into().unwrap(), &y_shares);
        let mut custom_struct = CustomStructForServerUpdate::new();
        custom_struct.add_multiple(ds, vs);
        ByteBuffer::from_vec(postcard::to_stdvec(&custom_struct).unwrap())
    });
    if err.get_code().is_success() {
        *result_buffer = result;
    } 
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_get_epoch(handle: u64, err: &mut ExternError) -> i32 {
    let result = SERVERS.call_with_output_mut(err, handle, |server| {
        server.get_epoch() as i32
    });
    if err.get_code().is_success() {
        result
    } else {
        err.get_code().code()
    }
}

// // error handling
// #[no_mangle]
// pub extern "C" fn allosaurus_user_random(
//     alpha: ByteArray,
//     s: ByteArray,
//     acc_params: ByteArray,
//     accumulator: ByteArray,
//     public_keys: ByteArray,
//     epoch: ByteArray,
//     result_buffer: &mut ByteBuffer,
// ) -> i32 {
//     let alpha_vec = alpha.to_vec();
//     let alpha_arr: &[u8; 32] = alpha_vec.as_slice().try_into().expect("Slice with incorrect length");
//     let alpha = SecretKey::from_bytes(alpha_arr);
//     let s_vec = s.to_vec();
//     let s_arr: &[u8; 32] = s_vec.as_slice().try_into().expect("Slice with incorrect length");
//     let s = SecretKey::from_bytes(s_arr);
//     let acc_params = acc_params_from_bytes(acc_params.to_vec()).unwrap();
//     let acc_vec = accumulator.to_vec();
//     let acc_array: &[u8; 96] = acc_vec.as_slice().try_into().expect("Slice with incorrect length");
//     let acc: Accumulator = G1Projective::from_uncompressed(acc_array).unwrap().into();
//     let public_keys = PublicKeys::from_bytes(public_keys.to_vec()).unwrap();
//     let epoch = usize::from_be_bytes(epoch.to_vec().as_slice().try_into().expect("Slice with incorrect length"));

//     let result = User::random(&alpha, &s, acc_params, acc, public_keys, epoch);
//     let result_bytes = result.to_bytes();
//     *result_buffer = ByteBuffer::from_vec(result_bytes.to_vec());
//     0
// }

// // error handling
// #[no_mangle]
// pub extern "C" fn allosaurus_user_create_witness(
//     user: ByteArray,
//     params: ByteArray,
//     server_handle: u64,
// ) -> i32 {
//     let mut user = User::from_bytes(&user.to_vec()).unwrap();
//     let params = acc_params_from_bytes(params.to_vec()).unwrap();
//     let server = SERVERS.get(Handle::from_u64(server_handle).unwrap(), |server| {
//         User::create_witness(&mut user, &params, server);
//         Ok::<(), HandleError>(())
//     }).unwrap();
//     0
// }

// // error handling
// #[no_mangle]
// pub extern "C" fn allosaurus_user_make_membership_proof(
//     user: ByteArray,
//     params: ByteArray,
//     public_keys: ByteArray,
//     challenge: ByteArray,
//     result_buffer: &mut ByteBuffer,
// ) -> i32 {
//     let user = User::from_bytes(&user.to_vec()).unwrap();
//     let params = acc_params_from_bytes(params.to_vec()).unwrap();
//     let public_keys = PublicKeys::from_bytes(public_keys.to_vec()).unwrap();
//     let challenge = challenge.to_fixed_array().unwrap();

//     let result = User::make_membership_proof(&user, &params, &public_keys, &challenge).unwrap();
//     let result_bytes = result.to_bytes();
//     *result_buffer = ByteBuffer::from_vec(result_bytes.to_vec());
//     0
// }

// // error handling
// #[no_mangle]
// pub extern "C" fn allosaurus_user_check_witness(
//     user: ByteArray,
//     params: ByteArray,
//     accumulator: ByteArray,
//     result_buffer: &mut ByteBuffer,
// ) -> i32 {
//     let user = User::from_bytes(&user.to_vec()).unwrap();
//     let params = acc_params_from_bytes(params.to_vec()).unwrap();
//     let acc_vec = accumulator.to_vec();
//     let acc_array: &[u8; 96] = acc_vec.as_slice().try_into().expect("Slice with incorrect length");
//     let acc: Accumulator = G1Projective::from_uncompressed(acc_array).unwrap().into();

//     match User::check_witness(&user, &params, &acc) {
//         Ok(()) => {
//             *result_buffer = ByteBuffer::from_vec(b"Witness valid".to_vec());
//             0
//         },
//         Err(_) => {
//             *result_buffer = ByteBuffer::from_vec(b"Witness invalid".to_vec());
//             -1
//         }
//     }
// }



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
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

    #[test]
    #[ignore]
    fn test_allosaurus_server_add_delete() {
        let mut err = ExternError::default();
        let server_handle = allosaurus_new_server(&mut err);

        let user_id = UserID::random().to_bytes();
        let user_id_bytearray = ByteArray {
            length: user_id.len(),
            data: user_id.as_ptr(),
        };
        let user_id_bytearray_2 = ByteArray {
            length: user_id.len(),
            data: user_id.as_ptr(),
        };

        let witness_vec = vec![0u8; 1024]; 
        let mut witness_buffer = ByteBuffer::from_vec(witness_vec);

        let acc_vec = vec![0u8; 1024];
        let mut acc_buffer = ByteBuffer::from_vec(acc_vec);

        allosaurus_server_add(server_handle, user_id_bytearray, &mut witness_buffer, &mut err);
        assert_eq!(err.get_code(), ErrorCode::SUCCESS);

        allosaurus_server_delete(server_handle, user_id_bytearray_2, &mut acc_buffer, &mut err);
        assert_eq!(err.get_code(), ErrorCode::SUCCESS);


        let handle = Handle::from_u64(server_handle).expect("Invalid handle");
        SERVERS.remove(handle).expect("Failed to remove server");
    }

}

// #[no_mangle]
// pub extern "C" fn allosaurus_server_witness(
//     handle: u64,
//     params: ByteArray,
//     user: ByteArray,
//     challenge: ByteArray,
//     response: ByteArray,
//     user_pub_key: ByteArray,
//     result_buffer: &mut ByteBuffer,
//     err: &mut ExternError,
// ) -> i32 {
//     let acc_param: AccParams = postcard::from_bytes(&params.to_vec()).unwrap();
//     let user: User = postcard::from_bytes(&user.to_vec()).unwrap();
//     let user_id = user.get_id();
//     let challenge = element_from_bytes(challenge.to_vec()).unwrap();
//     let response = element_from_bytes(response.to_vec()).unwrap();

//     let user_pub_key_vec = user_pub_key.to_vec();
//     let user_pub_key_array: &[u8; 96] = user_pub_key_vec.as_slice().try_into().expect("Slice with incorrect length");
//     let user_pub_key = G1Projective::from_uncompressed(user_pub_key_array).unwrap();

//     let result = SERVERS.call_with_result_mut(err, handle, move |server| {
//         match server.witness(&acc_param, &user_id, &challenge, &response, &user_pub_key) {
//             Some((witness, g1)) => {
//                 let witness_bytes = witness.to_bytes().to_vec();
//                 let g1_bytes = g1.to_uncompressed();
//                 let mut buffer = Vec::new();
//                 buffer.extend_from_slice(&witness_bytes.len().to_ne_bytes());
//                 buffer.extend_from_slice(&g1_bytes.len().to_ne_bytes());
//                 buffer.extend(&witness_bytes);
//                 buffer.extend(&g1_bytes);
//                 Ok(ByteBuffer::from_vec(buffer))
//             },
//             None => Err(ExternError::new_error(ErrorCode::new(-2), "unable to delete user_id".to_string()))
//         }
//     });
//     if err.get_code().is_success() {
//         *result_buffer = result;
//     }
//     err.get_code().code()

// }