# Anoncreds Revocation Manager
This is a revocation manager API backend written in Python that allows issuer, verifier, credential holder to revoke, verify, update AnonCreds credentials. It includes the base ALLOSAURUS revocation algorithm in the folder `agora-allosaurus-rs` written in Rust, the foreign function interface (FFI) functions in the `agora-allouraurus-py` in Python, and the backend API stored in the folder `revocation-manager-py` using FastAPI. 

## Tests
To test the FFI functions on the Rust end, cd into `agora-allosaurus-rs` and run
* `cargo test` # run all unit test
* `cargo test --features ffi -- ffi` # only run the test in the `ffi.rs` file. Note that in order for the test to work, must include ffi feature

To test the FFI functions in Python, 
1. Must build the ALLOSAURUS library in Rust first in order for Python to get the function calls. Run: 
`cargo build --release`
2. Then can run the test function in the test.ipynb Jupyter Notebook

## Docker
To set up the Docker container for this project:
1. Build Rust Library
`cd agora-alloraurus-rs && cargo build --release`
2. compile docker
`docker build -t {container_name} .`
3. run container with port specified
`docker run -p 4000:80 {container_name}`