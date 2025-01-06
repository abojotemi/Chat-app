from datetime import datetime, timezone
from pydantic import EmailStr
from sqlmodel import Field, Relationship
from api.models.abstract_base import AbstractBaseModel
import sqlalchemy.dialects.postgresql as pg



class User(AbstractBaseModel, table=True):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr = Field(unique=True)
    password: str
    is_verified: bool = Field(default=False)
    last_login: datetime = Field(default_factory=datetime.now)
    chats: list["Chat"] = Relationship(
        back_populates="user", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
