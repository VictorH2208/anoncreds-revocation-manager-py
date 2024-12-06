from contextlib import asynccontextmanager
import ctypes
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
import importlib.util
import asyncio
from datetime import datetime
import json
import requests
import base64

from models import *

# path = 'agora-allosaurus-py/allosaur/bindings.py' # line for docker file
path = '../agora-allosaurus-py/allosaur/bindings.py'

spec = importlib.util.spec_from_file_location("bindings", path)
bindings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bindings)

witness_cache = {}

# sample revocation file format
tmp_revocation_file = {
    "timestamp": 1630000000,
    "revoked":[
        {
            "user_guid": "test_holder",
            "deletion": "element_delete",
            "coefficient": "element_coefficient"
        }
    ]
}

async def update_cache_periodically():
    try:
        while True:
            current_time = datetime.now().timestamp()
            for user_id, data in witness_cache.items():
                updated_witness = allosaurus_multi_batch_update(user_id, data["witness"], data["timestamp"])
                witness_cache[user_id] = {
                    "witness": updated_witness,
                    "timestamp": current_time
                }
            print("Cache updated at: ", current_time)
            await asyncio.sleep(3600) # update cache every hour
    except asyncio.CancelledError:
        print("Cache update task cancelled")

async def app_lifespan(app: FastAPI):
    task = asyncio.create_task(update_cache_periodically())
    yield
    task.cancel()
    await task

app = FastAPI(lifespan=app_lifespan)


# function to get the all deltas from a file given given current witness and current timestamp?
def allosaurus_multi_batch_update(user_id, witness, timestamp, reovcation_file_path):
    
    def to_fixed_size_bytes(s, size):
        encoded = s.encode('utf-8')
        return encoded.ljust(size, b'\x00')[:size] 

    revocation_json = get_revocation_file(reovcation_file_path)
    revocation_file = json.loads(revocation_json)

    file_timestamp = revocation_file["timestamp"]
    revoked_list = revocation_file["revoked"]

    # check if the file is newer than the current timestamp
    # if it is not, return the witness
    if file_timestamp <= timestamp:
        return witness
    
    # if it is, update the witness

    # if the user is in the revoked list, return None
    all_revoked_guid = [r["user_guid"] for r in revoked_list]
    if user_id in all_revoked_guid:
        return None
    
    all_deletions = [r["deletion"] for r in revoked_list]
    all_coefficients = [r["coefficient"] for r in revoked_list]

    try:
        new_witness = bindings.multi_batch_update(witness, all_deletions, all_coefficients)
        encoded_witness = base64.b64encode(new_witness).decode('utf-8')
        return {"witness": encoded_witness, "timestamp": datetime.now().timestamp()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# function to retrieve the revocation file
def get_revocation_file(file_path):
    try:
        response = requests.get(file_path)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/")
def read_root():
    return {"Hello": "World"}


# holder to periodically check the deltas from the file
@app.post("/holder_witness_update")
def holder_witness_update(WitnessUpdateInput: WitnessUpdateInput):
    user_guid = WitnessUpdateInput.user_guid
    current_witness = WitnessUpdateInput.current_witness
    current_timestamp = WitnessUpdateInput.current_timestamp
    revocation_file_path = WitnessUpdateInput.revocation_file_url

    if user_guid not in witness_cache:
        updated_witness = allosaurus_multi_batch_update(user_guid, current_witness, current_timestamp, revocation_file_path)
        witness_cache[user_guid] = {
            "witness": updated_witness,
            "timestamp": current_timestamp
        }
    
    if witness_cache[user_guid]["witness"] is None:
        return JSONResponse(status_code=400, content={"message": "User has been revoked"})

    return witness_cache[user_guid]

# 1. how does the witness server knows which revocation file to access?
# the issuer has to provide it to the witness server 
# what about multiple issuers? how does the witness server know which issuer to get the revocation file from?

# 2. how does the witness server know which user to update the witness for?
# the holder has to provide the user_guid to the witness server? How?

# 3. What is y in the witness_update function? Who provides it?