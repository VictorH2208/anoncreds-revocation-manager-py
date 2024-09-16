from pydantic import BaseModel

class UserInput(BaseModel):
    user: str

class ProofInput(BaseModel):
    proof: str

class UserList(BaseModel):
    users: list[str]

class UpdateInput(BaseModel):
    user: str
    threshold: int