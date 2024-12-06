from pydantic import BaseModel

class WitnessUpdateInput(BaseModel):
    current_witness: str
    current_timestamp: int