from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from issuer import router as issuer_router
from holder import router as holder_router

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # This example hard-codes authentication check for simplicity
    if form_data.username == "admin" and form_data.password == "secret":
        # Normally, return a real JWT token
        return {"access_token": "fake-jwt-token", "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

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
