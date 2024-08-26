#!/usr/bin/python3

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
            os.path.dirname(__file__), f"{lib_prefix}{lib_name}{lib_suffix}"
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
        LIB = _load_library("oberon")

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
    _free_string(err)
    return handle

def server_add(handle: c_int64, user_id: bytes) -> None:
    err = FfiError()
    buffer = FfiByteBuffer()
    
