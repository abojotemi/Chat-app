from pydantic import BaseModel
from api.schemas.message import MessageSchema, MessageCreate


class ChatCreate(BaseModel):
    messages: list[MessageSchema] = []


class ChatUpdate(BaseModel):
    message: MessageCreate
