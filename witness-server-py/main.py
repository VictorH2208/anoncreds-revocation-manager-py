from contextlib import asynccontextmanager
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
url_cache = {
    "test_issuer": { "timestamp": datetime.now(), "deletions": [], "deletions_cnt": 0, "coefficients": [], "coefficients_cnt": 0}
}

async def update_cache_periodically():
    try:
        while True:
            current_time = datetime.now()
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
def allosaurus_multi_batch_update(user_id, witness, timestamp):
    revocation_json = get_revocation_file()
    revocation_file = json.loads(revocation_json)

    file_timestamp = revocation_file["timestamp"]
    deletions = revocation_file["deletions"] # assuming the deletions are already serialized using postcard and base64 encoded
    deletions_cnt = revocation_file["deletions_cnt"]
    coefficients = revocation_file["coefficients"] # assuming the coefficients are already serialized using postcard and base64 encoded
    coefficients_cnt = revocation_file["coefficients_cnt"]

    # check if the file is newer than the current timestamp
    # if it is not, return the witness
    if file_timestamp <= timestamp:
        return witness
    
    # if it is, update the witness
    # try:
    #     new_witness = bindings.multi_batch_update(witness, deletions, deletions_cnt, coefficients, coefficients_cnt)
    #     encoded_witness = base64.b64encode(new_witness).decode('utf-8')
    #     return {"witness": encoded_witness, "timestamp": datetime.now()}
    # except Exception as e:
    #     raise HTTPException(status_code=400, detail=str(e))


# pseudo function to retrieve the revocation file
def get_revocation_file():
    return json.dump(url_cache["test_issuer"])


@app.get("/")
def read_root():
    return {"Hello": "World"}


# pseudo function to store the revocation file url in the cache
@app.post("/issuer_revocation_file")
def issuer_revocation_file(IssuerInput: IssuerInput):
    url_cache[IssuerInput.user_guid] = IssuerInput.url_path
    return "URL added to cache"


# holder to periodically check the deltas from the file
@app.post("/holder_witness_update")
def holder_witness_update(WitnessUpdateInput: WitnessUpdateInput):
    user_guid = WitnessUpdateInput.user_guid
    current_witness = WitnessUpdateInput.current_witness
    current_timestamp = WitnessUpdateInput.current_timestamp

    if user_guid not in witness_cache:
        updated_witness = allosaurus_multi_batch_update(user_guid, current_witness, current_timestamp)
        witness_cache[user_guid] = {
            "witness": updated_witness,
            "timestamp": current_timestamp
        }

    return witness_cache[user_guid]

# 1. how does the witness server knows which revocation file to access?
# the issuer has to provide it to the witness server 
# what about multiple issuers? how does the witness server know which issuer to get the revocation file from?

# 2. how does the witness server know which user to update the witness for?
# the holder has to provide the user_guid to the witness server? How?