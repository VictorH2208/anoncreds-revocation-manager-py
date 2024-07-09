from fastapi import APIRouter, Depends, HTTPException, status, Body
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from test_pk import generate_key_pair, create_signature

router = APIRouter()

# Generate the key pair (private_key is used for signing, public_key for verification)
private_key, public_key = generate_key_pair()

# Example: Create a signature for testing
signature = create_signature("data", private_key)
print("==========================================")
print(signature)
print("==========================================")

class SignatureRequest(BaseModel):
    data: str
    signature: str

def verify_signature(data: str, signature: str) -> bool:
    try:
        decoded_signature = base64.b64decode(signature)
        public_key.verify(
            decoded_signature,
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def verify_issuer(signature_request: SignatureRequest = Body(...)) -> bool:
    if verify_signature(signature_request.data, signature_request.signature):
        return True
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid signature"
        )

@router.get("/data")
def read_issuer_data(signature_request: SignatureRequest = Body(...)):
    status = verify_issuer(signature_request)
    return {"data": "Sensitive issuer data", "user": "Issuer" if status else "Holder"}

@router.post("/init-revocation-registry")
def init_revocation_registry(signature_request: SignatureRequest = Body(...)):
    verify_issuer(signature_request)
    # Logic to set up a revocation registry
    return {"status": "Revocation registry set up"}

@router.post("/revoke-credential")
def revoke_credential(signature_request: SignatureRequest = Body(...)):
    verify_issuer(signature_request)
    # revoke a credential
    return {"status": "Credential revoked"}
