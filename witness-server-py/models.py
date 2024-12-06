from pydantic import BaseModel

class WitnessUpdateInput(BaseModel):
    user_guid: str
    current_witness: str # base64 encoded
    current_timestamp: int
    revocation_file_url: str

class IssuerInput(BaseModel):
    user_guid: str
    url_path: str