from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi_jwt_auth import AuthJWT
from db import create_tables
from schemas.settings import Settings
from routes.auth.auth_route import auth_route

app = FastAPI()

app.include_router(auth_route)

create_tables()


@AuthJWT.load_config
def get_config():
  return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
  return JSONResponse(
    status_code=exc.status_code,
    content={"detail": exc.message}
  )
  
@app.get('/')
def home():
  return 'hola'
    
    
    
    
    
    
    
    
    
    