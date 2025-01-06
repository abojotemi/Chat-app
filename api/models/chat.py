from sqlmodel import Field, Relationship
from api.models.abstract_base import AbstractBaseModel


class Chat(AbstractBaseModel, table=True):
    user_id: str = Field(foreign_key="user.id", ondelete="CASCADE")
    user: "User" = Relationship(back_populates="chats")
    messages: list["Message"] = Relationship(
        back_populates="chat", sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
