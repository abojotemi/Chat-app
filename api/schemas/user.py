from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(min_length=8, max_length=30)


class UserSchema(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr
    id: str
    last_login: datetime
    model_config = ConfigDict(extra='ignore')
    


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=30)
