from datetime import datetime, timezone
import sqlalchemy.dialects.postgresql as pg
from uuid import uuid4
from sqlmodel import Field, SQLModel


class AbstractBaseModel(SQLModel):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    last_login: datetime = Field(default_factory=datetime.now)
