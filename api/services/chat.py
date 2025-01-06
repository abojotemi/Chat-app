from api.config import Config
from api.models.access_token import Token
from api.models.user import User
from api.schemas.user import UserCreate, UserLogin, UserSchema
from api.schemas.chat import ChatCreate, ChatUpdate
from api.schemas.message import MessageCreate, MessageSchema
from api.models.chat import Chat
from api.models.message import Message

from datetime import datetime, timedelta, timezone
from sqlmodel import select, delete
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi import Depends, HTTPException, status


class ChatService:
    class ChatError:
        CHAT_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, "Chat doesn't exist")
        NOT_AUTHORIZED = HTTPException(
            status.HTTP_403_FORBIDDEN, "Not authorized to delete this chat"
        )

    async def get_chats_by_user_id(self, user_id: str, session: AsyncSession):
        statement = (
            select(Chat).where(Chat.user_id == user_id).order_by(Chat.created_at)
        )
        res = await session.exec(statement)
        return res.all()

    async def get_chat_by_id(self, chat_id: str, session: AsyncSession):
        statement = select(Chat).where(Chat.id == chat_id)
        res = await session.exec(statement)
        return res.first()

    async def add_new_message(
        self, user_id: str, chat_id: str, message: MessageCreate, session: AsyncSession
    ):
        chat = await self.get_chat_by_id(chat_id, session)
        if not chat:
            raise self.ChatError.CHAT_NOT_FOUND

        new_message = Message(chat_id=chat_id, user_id=user_id, **message.model_dump())
        session.add(new_message)
        await session.commit()
        await session.refresh(new_message)
        return new_message

    async def delete_chat(self, user_id: str, chat_id: str, session: AsyncSession):
        chat = await self.get_chat_by_id(chat_id, session)
        if not chat:
            raise self.ChatError.CHAT_NOT_FOUND

        # Check if the user owns this chat
        if chat.user_id != user_id:
            raise self.ChatError.NOT_AUTHORIZED

        await session.delete(chat)
        await session.commit()
