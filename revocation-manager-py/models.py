from pydantic import BaseModel

class UserInput(BaseModel):
    user: str

class ProofInput(BaseModel):
    proof: str