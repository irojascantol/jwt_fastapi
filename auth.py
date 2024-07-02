from datetime import timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from utils import dict2obj


router = APIRouter(
    prefix = '/auth',
    tags=['auth']
)

users_list = [{"id": 1, "username": "admin01", "hashed_password": "$2y$10$.71JpHineRKnVBwDAOwChejgBHCBbf3xAhTgN6zMweXrl/p6C.iw2"}, {"id": 2, "username": "admin02", "hashed_password": "$2y$10$gQwj4t0PIs8PbiQeWVVbV.w7ADf/U0jPKptcFmZ615yqrFsxhDWOC"}]

SECRET_KEY = 'a40bd8c1de406be2c0398f960f74b3e3a127c4ad4b1a637b0be6e4542df8f634'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


class CreateUserRequest (BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_request: CreateUserRequest):
    create_user_model = Users(
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
    )
    db.add(create_user_model)
    db.commit()

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validte user')
    
    token = create_access_token(user.username, user.id, timedelta(seconds=20))

    return {'access_token': token, 'token_type': 'bearer'}


def authenticate_user(username: str, password:str, db):
    user = [x for x in users_list if x["username"] == username]
    # user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    user_obj = dict2obj(user[0])
    # if not bcrypt_context.verify(password, user_obj.hashed_password):
    #     return False
    return user_obj

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'id': user_id, 'username': username}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        user_id: int = payload.get('id')
        username: str = payload.get('username')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate user.')

        return {'id': user_id, 'username': username}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate user.')