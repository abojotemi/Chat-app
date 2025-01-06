from datetime import datetime, timezone
from pydantic import EmailStr
from sqlmodel import Field, Relationship
from api.models.abstract_base import AbstractBaseModel


class Token(AbstractBaseModel, table=True):
    user_id: str = Field(foreign_key="user.id", ondelete="CASCADE")
    user: "User" = Relationship(
        sa_relationship_kwargs={"backref": "tokens"}
    )
    data: str
