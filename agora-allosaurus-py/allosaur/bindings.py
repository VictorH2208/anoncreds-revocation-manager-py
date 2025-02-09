import ctypes
import pdb
import os
import sys
from ctypes import (
    CDLL,
    POINTER,
    Structure,
    byref,
    string_at,
    c_char_p,
    c_int32,
    c_int64,
    c_uint64,
    c_ubyte,
    cast
)

from ctypes.util import find_library
from typing import Optional, Union

LIB: CDLL = None

class FfiByteBuffer(Structure):
    """A byte buffer allocated by python."""
    _fields_ = [
        ("length", c_int64),
        ("data", POINTER(c_ubyte)),
    ]


class FfiError(Structure):
    """An error allocated by python."""
    _fields_ = [
        ("code", c_int32),
        ("message", c_char_p),
    ]


def _decode_bytes(arg: Optional[Union[str, bytes, FfiByteBuffer]]) -> bytes:
    if isinstance(arg, FfiByteBuffer):
        return string_at(arg.data, arg.length)
    if isinstance(arg, memoryview):
        return string_at(arg.obj, arg.nbytes)
    if isinstance(arg, bytearray):
        return arg
    if arg is not None:
        if isinstance(arg, str):
            return arg.encode("utf-8")
    return bytearray()


def _encode_bytes(arg: Optional[Union[str, bytes, FfiByteBuffer]]) -> FfiByteBuffer:
    if isinstance(arg, FfiByteBuffer):
        return arg
    buf = FfiByteBuffer()
    if isinstance(arg, memoryview):
        buf.length = arg.nbytes
        if arg.contiguous and not arg.readonly:
            buf.data = (c_ubyte * buf.length).from_buffer(arg.obj)
        else:
            buf.data = (c_ubyte * buf.length).from_buffer_copy(arg.obj)
    elif isinstance(arg, bytearray):
        buf.length = len(arg)
        if buf.length > 0:
            buf.data = (c_ubyte * buf.length).from_buffer(arg)
    elif arg is not None:
        if isinstance(arg, str):
            arg = arg.encode("utf-8")
        buf.length = len(arg)
        if buf.length > 0:
            buf.data = (c_ubyte * buf.length).from_buffer_copy(arg)
    return buf


def _load_library(lib_name: str) -> CDLL:
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "lib")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")
        lib_path = os.path.join(
            os.path.dirname(os.getcwd()), f"agora-allosaurus-rs/target/release/{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        print ("Unknown platform for shared library")
    except OSError:
        print ("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        if sys.platform == "darwin":
            ld = os.getenv("DYLD_LIBRARY_PATH")
            lib_path = os.path.join(ld, "liboberon.dylib")
            if os.path.exists(lib_path):
                return CDLL(lib_path)

            ld = os.getenv("DYLD_FALLBACK_LIBRARY_PATH")
            lib_path = os.path.join(ld, "liboberon.dylib")
            if os.path.exists(lib_path):
                return CDLL(lib_path)
        elif sys.platform != "win32":
            ld = os.getenv("LD_LIBRARY_PATH")
            lib_path = os.path.join(ld, "liboberon.so")
            if os.path.exists(lib_path):
                return CDLL(lib_path)

        raise Exception(f"Error loading library: {lib_name}")
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise Exception(f"Error loading library: {lib_name}")


def _get_library() -> CDLL:
    global LIB
    if LIB is None:
        LIB = _load_library("agora_allosaurus_rs")
    return LIB

def _get_func(fn_name: str):
    return getattr(_get_library(), fn_name)

def _free_buffer(buffer: FfiByteBuffer):
    lib_fn = _get_func("allosaurus_byte_buffer_free")
    lib_fn(byref(buffer))


def _free_string(err: FfiError):
    lib_fn = _get_func("allosaurus_string_free")
    lib_fn(byref(err))


def _free_handle(handle: c_int64, err: FfiError):
    lib_fn = _get_func("allosaurus_create_proof_free")
    lib_fn(handle, byref(err))


def new_server() -> c_int64:
    err = FfiError()
    lib_fn = _get_func("allosaurus_new_server")
    lib_fn.restype = c_uint64

    handle = lib_fn(byref(err))
    if handle == 0:
        message = string_at(err.message)
        raise Exception(message)
    handle = c_uint64(handle)
    return handle


def new_user(server) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_new_user")
    lib_fn(server, byref(buffer), byref(err))

    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer


def server_add(server, user) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_add")
    lib_fn(server, _encode_bytes(user), byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer


def server_delete(server, user) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_delete")
    lib_fn(server, _encode_bytes(user), byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer


def server_get_epoch(server) -> int:
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_get_epoch")
    return lib_fn(server, byref(err))


def server_get_accumulator(server) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_get_accumulator")
    lib_fn(server, byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer


def server_get_witness_public_key(server) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_get_witness_public_key")
    lib_fn(server, byref(buffer), byref(err))
    print(buffer)
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer


def server_get_sign_public_key(server) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_get_sign_public_key")
    lib_fn(server, byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer


def server_get_public_keys(server) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_get_public_keys")
    lib_fn(server, byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer

def user_create_witness(server, user):
    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_user_create_witness")
    lib_fn(server, _encode_bytes(user), byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer

def user_make_membership_proof(server, user) -> c_int64:
    buffer = FfiByteBuffer()
    err = FfiError()
    challenge = bytearray(os.urandom(32))
    lib_fn = _get_func("allosaurus_user_make_membership_proof")
    lib_fn(server, _encode_bytes(user), _encode_bytes(challenge), byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer

def witness_check_membership_proof(server, proof) -> c_int64:
    err = FfiError()
    lib_fn = _get_func("allosaurus_witness_check_membership_proof")
    lib_fn(server, _encode_bytes(proof), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    return "Membership proof verified successfully"

def check_witness(user):
    lib_fn = _get_func("allosaurus_user_check_witness")
    err = lib_fn(_encode_bytes(user))
    if err != 0:
        raise Exception("Witness is invalid")
    return "Witness is valid"

def server_batch_delete(server, user_list):
    user_buffer = (FfiByteBuffer * len(user_list))()
    for i, tmp_user in enumerate(user_list):
        array_type = c_ubyte * len(tmp_user)
        c_array = array_type(*tmp_user)
        user_buffer[i].length = len(tmp_user)
        user_buffer[i].data = cast(c_array, POINTER(c_ubyte))

    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_server_update")
    lib_fn(user_buffer, len(user_list), server, byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer

def user_update(servers, user, threshold) -> c_int64:
    array_type = c_uint64 * len(servers)
    servers = array_type(*servers)

    buffer = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("allosaurus_user_update")
    lib_fn(servers, len(servers), _encode_bytes(user), threshold, byref(buffer), byref(err))
    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer

def witness_multi_batch_update(witness, y, deletions, coefficients) -> c_int64:
    
    def to_fixed_size_bytes(s, size):
        encoded = s.encode('utf-8')
        return encoded.ljust(size, b'\x00')[:size] 

    bytes_deletions = b"".join([to_fixed_size_bytes(d, 32) for d in deletions])
    bytes_coefficients = b"".join([to_fixed_size_bytes(c, 32) for c in coefficients])

    delete_byte_buffer = (ctypes.c_uint8 * len(bytes_deletions))(*bytes_deletions)
    delete_ptr = ctypes.cast(delete_byte_buffer, ctypes.POINTER(ctypes.c_uint8))
    deletion_len = len(bytes_deletions) // 32

    coeff_byte_buffer = (ctypes.c_uint8 * len(bytes_coefficients))(*bytes_coefficients)
    coefficient_ptr = ctypes.cast(coeff_byte_buffer, ctypes.POINTER(ctypes.c_uint8)) 
    coefficient_len = len(bytes_coefficients) // 32

    buffer = FfiByteBuffer()
    err = FfiError()

    lib_fn = _get_func("witness_multi_batch_update")
    lib_fn(witness, y, delete_ptr, deletion_len, coefficient_ptr, coefficient_len, byref(buffer), byref(err))

    if err.code != 0:
        message = string_at(err.message)
        raise Exception(message)
    buffer = _decode_bytes(buffer)
    return buffer