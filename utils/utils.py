from fastapi import FastAPI, Depends
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.responses import Response
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema
from passlib.context import CryptContext


#################### refresh_token_middleware ####################
#     middleware para analizar el access_token                   #
##################################################################
async def refresh_token_middleware(request, call_next):
  try:
    AuthJWT.jwt_required()
    return await call_next(request)
  except AuthJWTException:
    try:
      AuthJWT.jwt_refresh_token_required()
      current_user = AuthJWT.get_jwt_subject()
      new_access_token = AuthJWT.create_access_token(subject=current_user)
      response = await call_next(request)
      
      response.set_cookie(key="access_token", value=new_access_token)
      
      return await call_next(request)
    except AuthJWTException:
      return Response("Unauthorized", status_code=401)
##################################################################


#################### HASHING PASSWORD WITH BCRYPT ####################
#     configuracion para hasheo de password                          #
######################################################################
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto" )

def get_password_hash(password):
  return bcrypt_context.hash(password)

def verify_password(plain_password, hash_password):
  return bcrypt_context.verify(plain_password, hash_password)
######################################################################
    
    
#################### send_email ######################
#     configuracion para envio de email              #
###################################################### 
async def send_email(token: str, usr_email: str):
  
  conf = ConnectionConfig(
    MAIL_USERNAME="pilcapa2023@gmail.com",
    MAIL_PASSWORD="ofmmifkfjjtwqyfq",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    MAIL_FROM="pilcapa2023@gmail.com",
  )
  
  verification_url = f"http://localhost:8000/auth/verify_email/{token}"
  
  template = f"""
    <html>
      <body>
        <p>Hola,</p>
        <p>Gracias por registrarte. Haz clic en el siguiente enlace para verificar tu cuenta:</p>
        <p><a href="{verification_url}">verificar</a></p>
      </body>
      </html>
    """
  message = MessageSchema(
    subject="Bienvenido a Capa",
    # List of recipients, as many as you can pass
    recipients=[usr_email],
    body=template,
    subtype="html",
  )
  fm = FastMail(conf)
  await fm.send_message(message)
######################################################
    