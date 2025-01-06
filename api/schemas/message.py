from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class MessageCreate(BaseModel):
    role: Literal["user", "ai"]
    message: str = Field(min_length=3)


class MessageSchema(MessageCreate):
    id: str
    user_id: str
    chat_id: str
    created_at: datetime
