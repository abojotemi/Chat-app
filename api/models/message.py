from enum import Enum
from typing import Literal
from sqlmodel import Field, Relationship
from api.models.abstract_base import AbstractBaseModel


class Message(AbstractBaseModel, table=True):
    user_id: str = Field(foreign_key="user.id", ondelete="CASCADE")
    chat_id: str = Field(foreign_key="chat.id", ondelete="CASCADE")
    role: str
    message: str = Field(max_length=2048)
    user: "User" = Relationship(
        sa_relationship_kwargs={"backref": "messages"}
    )
    chat: "Chat" = Relationship(back_populates="messages")
