#![allow(unused_doc_comments, missing_docs)]
use crate::accumulator::Coefficient;
use crate::accumulator::Element;
use crate::utils::*;
use crate::custom_bytebuffer::*;
use ffi_support::{
    define_bytebuffer_destructor, define_handle_map_deleter, define_string_destructor, ByteBuffer,
    ConcurrentHandleMap, ErrorCode, ExternError,HandleError, Handle
};
use blsful::inner_types::*;
use lazy_static::lazy_static;
use std::{ptr, slice, vec::Vec};
use postcard;
use crate::accumulator::witness::MembershipWitness;

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
pub fn to_fixed_array<const N: usize>(&self) -> Option<[u8; N]> {
        if self.length == N && !self.data.is_null() {
            unsafe {
                let slice = slice::from_raw_parts(self.data, self.length);
                let array: Result<[u8; N], _> = slice.try_into();
                array.ok()
            }
        } else {
            None
        }
    }
}

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
            *err = ExternError::new_error(ErrorCode::new(-2), "unable to create new user".to_string());
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
    user_bytes: *const ByteArray,
    user_cnt: usize,
    server_handle: u64,
    result_buffer: &mut ByteBuffer,
    err: &mut ExternError,
) ->i32 {
    let user_bytes = unsafe { slice::from_raw_parts(user_bytes, user_cnt) };
    let users: Vec<User> = user_bytes.iter().map(|user| postcard::from_bytes(&user.to_vec()).unwrap()).collect();
    let user_ids: Vec<Scalar> = users.iter().map(|user| {
        let user_id: UserID = user.get_id();
        let Element(scalar) = user_id;
        scalar
    }).collect();
    // println!("user_ids: {:?}", user_ids);
    let result = SERVERS.call_with_output_mut(err, server_handle, move |server| {
        let (ds, vs) = server.update(server.get_epoch(), &user_ids);
        println!("ds: {:?}, vs: {:?}", ds, vs);
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

#[no_mangle]
pub extern "C" fn allosaurus_server_get_accumulator(handle: u64, result_buffer: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let result = SERVERS.call_with_output_mut(err, handle, |server| {
        let acc = server.get_accumulator();
        ByteBuffer::from_vec(postcard::to_stdvec(&acc).unwrap())
    });
    if err.get_code().is_success() {
        *result_buffer = result;
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_get_witness_public_key(handle: u64, result_buffer: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let result = SERVERS.call_with_output_mut(err, handle, |server| {
        let pk = server.get_witness_public_key();
        ByteBuffer::from_vec(postcard::to_stdvec(&pk).unwrap())
    });
    if err.get_code().is_success() {
        *result_buffer = result;
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_get_sign_public_key(handle: u64, result_buffer: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let result = SERVERS.call_with_output_mut(err, handle, |server| {
        let pk = server.get_sign_public_key();
        ByteBuffer::from_vec(postcard::to_stdvec(&pk).unwrap())
    });
    if err.get_code().is_success() {
        *result_buffer = result;
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_server_get_public_keys(handle: u64, result_buffer: &mut ByteBuffer, err: &mut ExternError) -> i32 {
    let result = SERVERS.call_with_output_mut(err, handle, |server| {
        let pks = server.get_public_keys();
        ByteBuffer::from_vec(postcard::to_stdvec(&pks).unwrap())
    });
    if err.get_code().is_success() {
        *result_buffer = result;
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_user_create_witness(
    server_handle: u64,
    user: ByteArray,
    user_buffer: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let mut user: User = postcard::from_bytes(&user.to_vec()).unwrap();
    let result = SERVERS.get(Handle::from_u64(server_handle).unwrap(), |server| {
        user.create_witness(&AccParams::default(), &server);
        Ok::<User, HandleError>(user)
    });
    match result {
        Ok(user) => {
            *user_buffer = ByteBuffer::from_vec(postcard::to_stdvec(&user).unwrap());
            0
        },
        Err(_) => {
            *err = ExternError::new_error(ErrorCode::new(-2), "unable to create witness".to_string());
            -1
        }
    };
    err.get_code().code()
}


#[no_mangle]
pub extern "C" fn allosaurus_user_check_witness(
    user: ByteArray,
) -> i32 {
    let user: User = postcard::from_bytes(&user.to_vec()).unwrap();
    let params = AccParams::default();
    match user.check_witness(&params, &user.get_accumulator()) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

#[no_mangle]
pub extern "C" fn allosaurus_user_make_membership_proof(
    server_handle: u64,
    user: ByteArray,
    challenge: ByteArray,
    proof_buffer: &mut ByteBuffer,
    err: &mut ExternError
) -> i32 {
    let user: User = postcard::from_bytes(&user.to_vec()).unwrap();
    let params = AccParams::default();
    let challenge = challenge.to_fixed_array().unwrap();
    let result = SERVERS.get(Handle::from_u64(server_handle).unwrap(), |server| {
        let proof = user.make_membership_proof(&params, &server.get_public_keys(), &challenge);
        let custom_membership_proof = CustomStructForMembershipProof::new(proof.unwrap(), challenge);
        let buffer = ByteBuffer::from_vec(postcard::to_stdvec(&custom_membership_proof).unwrap());
        Ok::<ByteBuffer, HandleError>(buffer)
    });
    match result {
        Ok(proof) => {
            *proof_buffer = proof;
            0
        },
        Err(_) => {
            *err = ExternError::new_error(ErrorCode::new(-2), "Make membership proof failed".to_string());
            -1
        }
    };
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_witness_check_membership_proof(
    server_handle: u64,
    proof: ByteArray,
    err: &mut ExternError
) -> i32 {
    let custom_membership_proof: CustomStructForMembershipProof = postcard::from_bytes(&proof.to_vec()).unwrap();
    let params = AccParams::default();
    let result = SERVERS.get(Handle::from_u64(server_handle).unwrap(), |server| {
        let proof = custom_membership_proof.proof;
        let challenge = custom_membership_proof.challenge;
        if Witness::check_membership_proof(&proof, &params, &server.get_public_keys(), &server.get_accumulator(), &challenge) {
            Ok::<(), HandleError>(())
        } else {
            Err(HandleError::NullHandle)
        }
    });
    match result {
        Ok(_) => 0,
        Err(_) => {
            *err = ExternError::new_error(ErrorCode::new(-2), "Verify membership proof failed".to_string());
            -1
        }
    };
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn allosaurus_user_update(
    server_list: *const u64,
    server_cnt: usize,
    user: ByteArray,
    threshold: u64,
    new_user: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32{ 
    let mut tmp_err = ExternError::default();
    let mut user: User = postcard::from_bytes(&user.to_vec()).unwrap();
    let server_handles = unsafe { slice::from_raw_parts(server_list, server_cnt) };
    let mut server_refs = Vec::<Server>::with_capacity(server_cnt);
    server_handles.iter().for_each(|&handle| {
        let result = SERVERS.call_with_output(&mut tmp_err, handle, |server| {    
            ByteBuffer::from_vec(postcard::to_stdvec(server).unwrap())
        });
        let server = postcard::from_bytes(result.as_slice()).unwrap();
        server_refs.push(server);

    });
    match user.update(&server_refs[..], threshold as usize) {
        Ok(()) => {
            *new_user = ByteBuffer::from_vec(postcard::to_stdvec(&user).unwrap());
            0
        },
        Err(_) => {
            println!("Err");
            *err = ExternError::new_error(ErrorCode::new(-2), "unable to update user".to_string());
            -1
        },
    }
}

#[no_mangle]
pub extern "C" fn witness_multi_batch_update(
    current_witness: ByteArray,
    y_element: ByteArray,
    d_list: *const ByteArray,
    d_cnt: usize,
    c_list: *const ByteArray,
    c_cnt: usize,
    witness_buffer: &mut ByteBuffer,
) -> i32 {
    // Deserialize the MembershipWitness 
    let mut current_witness: MembershipWitness = postcard::from_bytes(&current_witness.to_vec()).unwrap();

    // Deserialize y Element
    let y_element: Element = postcard::from_bytes(&y_element.to_vec()).unwrap();
    
    // Deserialize d_list and c_list in loop and store them in a vector
    let d_elements: Vec<Element> = unsafe { slice::from_raw_parts(d_list, d_cnt) }
        .iter()
        .map(|d| Element::from_bytes(d.to_fixed_array().unwrap()).unwrap())
        .collect();

    let c_coefficients: Vec<Coefficient> = unsafe { slice::from_raw_parts(c_list, c_cnt) }
        .iter()
        .map(|c| Coefficient::from_bytes(c.to_fixed_array().unwrap()).unwrap())
        .collect();

    let empty_a: Vec<Element> = Vec::new();
    let deltas: Vec<(_, _, _)> = std::iter::repeat(empty_a.as_slice())  
    .zip(d_elements.iter().map(|d| slice::from_ref(d)))  
    .zip(c_coefficients.iter().map(|c| slice::from_ref(c)))  
    .map(|((a, d), c)| (a, d, c))
    .collect();

    let result= MembershipWitness::multi_batch_update(&mut current_witness, y_element, &deltas);
    *witness_buffer = ByteBuffer::from_vec(postcard::to_stdvec(&result).unwrap());
    0
}



#[cfg(test)]
mod tests {
    use crate::accumulator::{Accumulator, PublicKey, SecretKey};
    use super::*;

    #[test]
    #[ignore]
    fn temp_test() {
        let params = AccParams::default();
        let mut server = Server::new(&params);
        let mut user = User::new(&mut server, UserID::random());
        server.add(user.get_id());
        user.create_witness(&params, &server);
        let result = User::check_witness(&user, &params, &server.get_accumulator());
        assert_eq!(result, Ok(()));
    }

    #[test]
    #[ignore]
    fn test_desearialize_witness() {
        let key = SecretKey::new(Some(b"1234567890"));
        let pubkey = PublicKey::from(&key);
        let elements = [
            Element::hash(b"3"),
            Element::hash(b"4"),
            Element::hash(b"5"),
            Element::hash(b"6"),
            Element::hash(b"7"),
            Element::hash(b"8"),
            Element::hash(b"9"),
        ];
        let y = elements[3];
        let mut acc = Accumulator::with_elements(&key, &elements);
        let mut wit = MembershipWitness::new(y, acc, &key).unwrap();

        let current_witness = postcard::to_stdvec(&wit).unwrap();
        let witness = postcard::from_bytes::<MembershipWitness>(&current_witness).unwrap();

        assert_eq!(witness, wit);
    }

}