from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from issuer import router as issuer_router
from holder import router as holder_router

app = FastAPI()

app.include_router(
    issuer_router,
    prefix="/issuer",
    tags=["issuer"],
    dependencies=[],
    responses={403: {"description": "Operation forbidden"}}
)

app.include_router(
    holder_router,
    prefix="/holder",
    tags=["holder"]
)
