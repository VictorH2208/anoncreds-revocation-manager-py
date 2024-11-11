What is done:
- Converted server, witness, and user functions to FFI calls in the ffi.rs file.
- Implemented corresponding Python functions for the FFI calls, along with their unit tests.
- Established a revocation manager endpoint using FastAPI.
- Configured the Dockerfile for the revocation manager deployment

What needs to be done:
- Separating witness server from revocation manager
- Configure its Dockerfile
