# Anoncreds Revocation Manager
This is a revocation manager backend API written in Python that allows issuer, verifier, credential holder to revoke, verify, update AnonCreds credentials. It includes 
1. The base ALLOSAURUS revocation algorithm in the folder `agora-allosaurus-rs` written in Rust cited from https://github.com/LF-Decentralized-Trust-labs/agora-allosaurus-rs and paper: https://eprint.iacr.org/2022/1362,
2. The foreign function interface (FFI) functions in the `agora-allouraurus-py` in Python,
3. The revocation manager backend API stored in the folder `revocation-manager-py` using FastAPI.
4. The witness server API stored in the folder `witness-server-py`

For more details of the revocation manager refer to https://hackmd.io/@swcurran/HJ4LaLFeyx

## Tests
To test the FFI functions on the Rust end, cd into `agora-allosaurus-rs` and run
* `cargo test` # run all unit test
* `cargo test --features ffi -- ffi` # run test for ffi. Note: --features ffi enables the ffi feature in test.

To test the FFI functions in Python, 
1. You must pre build the ALLOSAURUS library in Rust first in order for Python to get the function calls. Run: \
`cargo build --release`
2. Then verify the `libagora_allosaurus-rs.so` is in the target folder
3. Then you can run the test functions in order in the test.ipynb Jupyter Notebook

## Running locally
To run the server locally, cd into the backend server that you want to run and run
* `uvicorn main:app --reload` 

then go to http://127.0.0.1:8000/docs to see the entire swagger ui

## Docker
To set up the Docker containers:
1. Pre build Rust Library and then place the `libagora_allosaurus-rs.so` in the main folder\
`cd agora-alloraurus-rs && cargo build --release`
2. Compile docker using the command below\
`docker build -f {filename} -t {container_name} .`
3. run container with port specified\
`docker run -p 4000:80 {container_name}`

then go to http://localhost:4000/docs for the swagger ui

## Docker for network locally
You can also choose to run multiple service locally as a network
1. First create the network\
`docker network create {my-network}`
2. Build containers\
`docker build -f {filename} -t {container_name} .`
3. Launch the services on the network\
`docker run -p 4000:80 --network {my-network} --name service4000 {container_name}`\
`docker run -p 5000:80 --network {my-network} --name service5000 {container_name}`