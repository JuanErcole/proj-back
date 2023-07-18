from pydantic import BaseModel, EmailStr, Field

class UserLogin(BaseModel):
  usr_email: EmailStr
  usr_password: str = Field(min_length=6, max_length=20)
  
class UserCreate(UserLogin):
  usr_name: str = Field(regex=r"^\w+(?:\s\w+)*$", min_length=3, max_length=50)
  
class User(UserCreate):
  usr_id: int
  usr_role: str = 'client'
  usr_enabled: bool = False
  
  class Config:
    orm_mode = True







