from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError
from api.db.connect import get_session
from api.models.user import User
from api.services.user import user_service, oauth2_scheme
from api.schemas.user import UserCreate, UserLogin, UserSchema
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.sql import select
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter(prefix='/users')



@router.get('/{id}', response_model=UserSchema)
async def get_user_info(id: str, session: AsyncSession = Depends(get_session), authentication = Depends(user_service.get_current_user)):
    result = await user_service.get_user_by_id(id, session)
    if result:
        return result
    raise user_service.UserError.USER_NOT_FOUND
    
@router.post("/", response_model=UserSchema)
async def create_user(user_data: UserCreate, session: AsyncSession = Depends(get_session)):
    result = await user_service.create_user(user_data, session)
    return result

@router.get('/', response_model=list[UserSchema])
async def get_users_info(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(user_service.get_current_user)
):
    statement = select(User)
    result = await session.exec(statement)
    return result.all()

@router.post('/login')
async def login(
    user_data: UserLogin,
    session: AsyncSession = Depends(get_session)
):
    user = await user_service.login_user(user_data, session)
    if not user:
        raise user_service.UserError.INVALID_CREDENTIALS
    
    access_token = await user_service.create_access_token_in_db(user, session)
    return {"access_token": access_token, "token_type": "bearer"}

@router.delete('/{user_id}')
async def delete_user(
    user_id: str,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(user_service.get_current_user)
):
    result = await user_service.delete_user(user_id, current_user, session)
    if result:
        return {"message": "User deleted successfully"}
    raise user_service.UserError.DATABASE_ERROR

@router.post('/logout')
async def logout(
    session: AsyncSession = Depends(get_session),
    token: str = Depends(oauth2_scheme)
):
    result = await user_service.revoke_token(token, session)
    if result:
        return {"message": "Logged out successfully"}
    raise user_service.UserError.DATABASE_ERROR
    
        