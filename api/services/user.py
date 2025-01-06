from datetime import datetime, timedelta, timezone
from sqlmodel import select, delete
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi import Depends, HTTPException, status

import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

from api.config import Config
from api.db.connect import get_session
from api.models.access_token import Token
from api.models.user import User
from api.schemas.user import UserCreate, UserLogin, UserSchema
from api.schemas.chat import ChatCreate

from api.models.chat import Chat
from api.models.message import Message

import logging

import re

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class UserService:

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)

    class UserError:
        INVALID_CREDENTIALS = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Credentials"
        )
        USER_NOT_FOUND = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
        CREDENTIAL_EXCEPTION = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        USER_ALREADY_EXIST = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with email already exists",
        )
        DATABASE_ERROR = HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed",
        )
        INVALID_TOKEN = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or expired",
        )
        UNAUTHORIZED_DELETE = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this user",
        )
        TOKEN_REVOKED = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked"
        )
        ACCOUNT_LOCKED = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked due to too many failed attempts",
        )
        WEAK_PASSWORD = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least 8 characters, including uppercase, lowercase, number and special character",
        )

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def _get_password_hash(self, password: str) -> str:
        return pwd_context.hash(password)

    async def _exists(self, email: str, session: AsyncSession) -> bool:
        res = await self.get_user_by_email(email, session)
        return bool(res)

    def _validate_password_strength(self, password: str) -> bool:
        if len(password) < 8:
            return False
        if not re.search(r"[A-Z]", password):  # Uppercase
            return False
        if not re.search(r"[a-z]", password):  # Lowercase
            return False
        if not re.search(r"\d", password):  # Digit
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):  # Special char
            return False
        return True

    async def create_user(self, user_data: UserCreate, session: AsyncSession) -> User:
        try:
            user_exists = await self._exists(user_data.email, session)
            if user_exists:
                raise self.UserError.USER_ALREADY_EXIST

            # Validate password strength
            if not self._validate_password_strength(user_data.password):
                raise self.UserError.WEAK_PASSWORD

            hashed_password = self._get_password_hash(user_data.password)

            user_data.password = hashed_password

            user = User.model_validate(user_data.model_dump())

            session.add(user)
            await session.commit()
            await session.refresh(user)

            access_token = self.create_access_token(user)
            if access_token:
                token = Token(user_id=user.id, data=access_token)
                session.add(token)
                await session.commit()

            return user
        except HTTPException as e:
            await session.rollback()
            raise e
        except Exception as e:
            await session.rollback()
            logger.error(f"Error creating user: {str(e)}")
            
            raise self.UserError.DATABASE_ERROR

    async def get_user_by_email(self, email: str, session: AsyncSession) -> User | None:
        statement = select(User).where(User.email == email)
        res = await session.exec(statement)
        return res.first()

    async def get_user_by_id(self, id: str, session: AsyncSession) -> User | None:
        statement = select(User).where(User.id == id)
        res = await session.exec(statement)
        return res.first()

    def create_access_token(self, user: User) -> str:
        payload = {"id": user.id, "email": user.email, "username": user.username}

        expiry_time = datetime.now(timezone.utc) + timedelta(
            minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES
        )

        payload.update({"exp": expiry_time})

        encoded_jwt = jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.ALGORITHM)

        return encoded_jwt

    async def validate_token(self, token: str, session: AsyncSession) -> bool:
        try:
            # Verify token exists in database
            statement = select(Token).where(Token.data == token)
            result = await session.exec(statement)
            db_token = result.first()

            if not db_token:
                return False

            # Verify token hasn't expired
            payload = jwt.decode(
                token, Config.JWT_SECRET, algorithms=[Config.ALGORITHM]
            )
            expiry = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)

            if datetime.now(timezone.utc) >= expiry:
                await self.revoke_token(token, session)
                return False

            return True
        except InvalidTokenError:
            return False

    async def get_current_user(
        self, session: AsyncSession = Depends(get_session), token: str = Depends(oauth2_scheme)
    ):
        try:
            # First validate the token
            is_valid = await self.validate_token(token, session)
            if not is_valid:
                raise self.UserError.INVALID_TOKEN

            payload = jwt.decode(
                token, Config.JWT_SECRET, algorithms=[Config.ALGORITHM]
            )
            email: str = payload.get("email")
            if email is None:
                raise self.UserError.CREDENTIAL_EXCEPTION

            user = await self.get_user_by_email(email=email, session=session)
            if user is None:
                raise self.UserError.CREDENTIAL_EXCEPTION

            return user
        except InvalidTokenError:
            raise self.UserError.CREDENTIAL_EXCEPTION

    async def authenticate_user(self, user_data: UserLogin, session: AsyncSession):
        user = await self.get_user_by_email(user_data.email, session)
        if not user:
            return False

        # Check if account is locked
        if not await self._check_login_attempts(user):
            raise self.UserError.ACCOUNT_LOCKED

        is_valid = self._verify_password(user_data.password, user.password)
        await self._update_login_attempts(user, is_valid, session)

        return user if is_valid else False

    async def login_user(self, user: UserLogin, session: AsyncSession):
        user = await self.authenticate_user(user, session)
        if not user:
            raise self.UserError.INVALID_CREDENTIALS

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        session.add(user)

        access_token = await self.create_access_token_in_db(user, session)
        return user

    async def create_new_chat(
        self, user_id: str, chat_data: ChatCreate, session: AsyncSession
    ):
        # Verify user exists
        user = await self.get_user_by_id(user_id, session)
        if not user:
            raise self.UserError.USER_NOT_FOUND

        # Create new chat
        new_chat = Chat(user_id=user_id)
        session.add(new_chat)
        await session.flush()

        # Add messages if any exist in chat_data
        if chat_data.messages:
            for message_data in chat_data.messages:
                message = Message(
                    chat_id=new_chat.id, user_id=user_id, **message_data.model_dump()
                )
                session.add(message)

        await session.commit()
        await session.refresh(new_chat)
        return new_chat

    async def _cleanup_old_tokens(self, user_id: str, session: AsyncSession):
        statement = delete(Token).where(Token.user_id == user_id)
        await session.exec(statement)

    async def create_access_token_in_db(self, user: User, session: AsyncSession):
        # Cleanup old tokens
        await self._cleanup_old_tokens(user.id, session)

        # Create new token
        access_token = self.create_access_token(user)
        token = Token(user_id=user.id, data=access_token)
        session.add(token)
        await session.commit()
        return access_token

    async def delete_user(
        self, user_id: str, current_user: User, session: AsyncSession
    ) -> bool:
        try:
            # Verify user exists
            user = await self.get_user_by_id(user_id, session)
            if not user:
                raise self.UserError.USER_NOT_FOUND

            # Verify current user has permission to delete (only allow users to delete themselves)
            if current_user.id != user_id:
                raise self.UserError.UNAUTHORIZED_DELETE

            # Delete user (cascade will handle related records)
            await session.delete(user)
            await session.commit()

            return True

        except Exception as e:
            await session.rollback()
            if isinstance(e, HTTPException):
                raise e
            raise self.UserError.DATABASE_ERROR

    async def revoke_token(self, token: str, session: AsyncSession) -> bool:
        try:
            statement = delete(Token).where(Token.data == token)
            await session.exec(statement)
            await session.commit()
            return True
        except Exception:
            await session.rollback()
            raise self.UserError.DATABASE_ERROR

    async def _check_login_attempts(self, user: User) -> bool:
        if (
            user.failed_login_attempts >= self.MAX_LOGIN_ATTEMPTS
            and user.last_failed_login
            and datetime.now(timezone.utc) - user.last_failed_login
            < self.LOCKOUT_DURATION
        ):
            return False
        return True

    async def _update_login_attempts(
        self, user: User, success: bool, session: AsyncSession
    ):
        if success:
            user.failed_login_attempts = 0
            user.last_failed_login = None
        else:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login = datetime.now(timezone.utc)
        session.add(user)
        await session.commit()


user_service = UserService()
