from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class UpdateRequest(BaseModel):
    user_id: int
    new_data: str

@router.post("/update")
def update_data(request: UpdateRequest):
    return {"status": "Data updated", "user_id": request.user_id, "new_data": request.new_data}
