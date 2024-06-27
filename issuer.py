# issuer.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    if token == "fake-jwt-token":
        return {"username": "issuer_user"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

@router.get("/data")
def read_issuer_data(user: dict = Depends(get_current_user)):
    return {"data": "Sensitive issuer data", "user": user["username"]}
