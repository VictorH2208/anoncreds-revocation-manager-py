from pydantic import BaseModel

class WitnessUpdateInput(BaseModel):
    user_guid: str
    current_witness: str # base64 encoded
    current_timestamp: int

class IssuerInput(BaseModel):
    user_guid: str
    url_path: str