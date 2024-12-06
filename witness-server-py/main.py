from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import importlib.util
import base64
import ctypes
import httpx

from .models import *

path = 'agora-allosaurus-py/allosaur/bindings.py' 

spec = importlib.util.spec_from_file_location("bindings", path)
bindings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bindings)

app = FastAPI()

witness_cache = {}

# holder to periodically check the deltas from the file
@app.get("/holder_witness_update")
def holder_witness_update(WitnessUpdateInput: WitnessUpdateInput):
    current_witness = WitnessUpdateInput.current_witness
    current_timestamp = WitnessUpdateInput.current_timestamp
    pass

# function to get the all deltas from a file given given current witness and current timestamp?
def allosaurus_multi_batch_update():
    pass

# function to retrieve the revocation file
def get_revocation_file(file_path: str):
    pass


    
@app.get("/")
def read_root():
    return {"Hello": "World"}