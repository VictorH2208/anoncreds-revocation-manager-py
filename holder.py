from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class UpdateRequest(BaseModel):
    user_id: int
    new_data: str

@router.post("/update")
def update_data(request: UpdateRequest):
    return {"status": "Data updated", "user_id": request.user_id, "new_data": request.new_data}

# A verify endpoint for the holder to send an handler and get a response of whether its credential is verified or not
@router.post("/verify")
def verify_credential():
    # Logic to verify a credential
    return {"status": "Credential verified"}