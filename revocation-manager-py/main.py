from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
import importlib.util
import base64
import ctypes
from .models import *
# from models import *

path = 'agora-allosaurus-py/allosaur/bindings.py' 
# path = '../agora-allosaurus-py/allosaur/bindings.py' 

spec = importlib.util.spec_from_file_location("bindings", path)
bindings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bindings)

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.registry = bindings.new_server()
    print(f"Server started: {app.state.registry}")
    yield
    print("Server shutting down")

app = FastAPI(lifespan=lifespan)

def get_registry_state():
    return app.state.registry

@app.get("/server")
def get_server():
    # return {"registry": f"{get_registry_state()}"}
    bytes_data = ctypes.string_at(ctypes.addressof(app.state.registry), ctypes.sizeof(app.state.registry))
    encoded_data = base64.b64encode(bytes_data)
    return encoded_data.decode('utf-8')

@app.get("/new_user")
def new_user():
    server = get_registry_state()
    user = bindings.new_user(server)
    encoded_user = base64.b64encode(user).decode('utf-8')
    return {"user": encoded_user}

@app.post("/server_add")
def server_add(user_input: UserInput):
    try:
        encoded_user_str = user_input.user
        user = base64.b64decode(encoded_user_str)
        server = get_registry_state()
        membership_witness = bindings.server_add(server, user)
        encoded_witness = base64.b64encode(membership_witness).decode('utf-8')
        return {"Add Successful, encoded witness is ": encoded_witness}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/server_delete")
def server_delete(user_input: UserInput):
    try:
        encoded_user_str = user_input.user
        user = base64.b64decode(encoded_user_str)
        server = get_registry_state()
        accumulator = bindings.server_delete(server, user)
        encoded_accumulator = base64.b64encode(accumulator).decode('utf-8')
        return {"Delete Successful, accumulator is": encoded_accumulator}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/server_batch_delete")
def server_batch_delete(user_list_input: UserList):
    try:
        user_list = user_list_input.users
        user_list = [base64.b64decode(encoded_user_str) for encoded_user_str in user_list]
        server = get_registry_state()
        accumulator = bindings.server_batch_delete(server, user_list)
        encoded_accumulator = base64.b64encode(accumulator).decode('utf-8')
        return {"Batch delete successful, accumulator is": encoded_accumulator}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/user_create_witness")
def user_create_witness(user_input: UserInput):
    try:
        encoded_user_str = user_input.user
        user = base64.b64decode(encoded_user_str)
        server = get_registry_state()
        user = bindings.user_create_witness(server, user)
        encoded_user = base64.b64encode(user).decode('utf-8')
        return {"user": encoded_user}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/user_check_witness")
def user_check_witness(user_input: UserInput):
    try:
        encoded_user_str = user_input.user
        user = base64.b64decode(encoded_user_str)
        bindings.check_witness(user)
        return {"Witness verified successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/user_make_membership_proof")
def user_make_membership_proof(user_input: UserInput):
    try:
        encoded_user_str = user_input.user
        user = base64.b64decode(encoded_user_str)
        server = get_registry_state()
        membership_proof = bindings.user_make_membership_proof(server, user)
        encoded_membership_proof = base64.b64encode(membership_proof).decode('utf-8')
        return {"Membership proof is": encoded_membership_proof}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/witness_check_membership_proof")
def witness_check_membership_proof(proof_input: ProofInput):
    try:
        encoded_proof_str = proof_input.proof
        proof = base64.b64decode(encoded_proof_str)
        server = get_registry_state()
        bindings.witness_check_membership_proof(server, proof)
        return {"Membership proof verified successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.post("/user_mpc_update")
def user_update(update_input: UpdateInput):
    try:
        encoded_user_str = update_input.user
        user = base64.b64decode(encoded_user_str)
        servers = get_registry_state()
        accumulator = bindings.user_update([servers], user, update_input.threshold)
        encoded_accumulator = base64.b64encode(accumulator).decode('utf-8')
        return {"Update successful, accumulator is": encoded_accumulator}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@app.get("/server_get_epoch")
def server_get_epoch():
    server = get_registry_state()
    epoch = bindings.server_get_epoch(server)
    return {"Current epoch is": epoch}

@app.get("/server_get_accumulator")
def server_get_accumulator():
    server = get_registry_state()
    accumulator = bindings.server_get_accumulator(server)
    encoded_accumulator = base64.b64encode(accumulator).decode('utf-8')
    return {"Current accumulator is": encoded_accumulator}

@app.get("/server_get_witness_public_key")
def server_get_witness_public_key():
    server = get_registry_state()
    witness_public_key = bindings.server_get_witness_public_key(server)
    encoded_witness_public_key = base64.b64encode(witness_public_key).decode('utf-8')
    return {"Current witness public key is": encoded_witness_public_key}

@app.get("/server_get_sign_public_key")
def server_get_sign_public_key():
    server = get_registry_state()
    sign_public_key = bindings.server_get_sign_public_key(server)
    encoded_sign_public_key = base64.b64encode(sign_public_key).decode('utf-8')
    return {"Current sign public key is": encoded_sign_public_key}

@app.get("/server_get_public_keys")
def server_get_public_keys():
    server = get_registry_state()
    public_keys = bindings.server_get_public_keys(server)
    encoded_public_keys = base64.b64encode(public_keys).decode('utf-8')
    return {"Current public keys are": encoded_public_keys}
    
@app.get("/")
def read_root():
    return {"Hello": "World"}