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
    prefix = '/product',
    tags=['product']
)

product_list = [{"id": 1, "title": "candado"}, {"id": 2, "title": "tranca"}]

SECRET_KEY = 'a40bd8c1de406be2c0398f960f74b3e3a127c4ad4b1a637b0be6e4542df8f634'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


class Token(BaseModel):
    access_token: str
    token_type: str


async def get_current_products(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # if username is None or user_id is None:
        #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
        #     detail='Could not validate user.')
        return {'content': product_list}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate user.')

product_dependency = Annotated[dict, Depends(get_current_products)]

@router.get("/", status_code=status.HTTP_200_OK)
# async def user(user: user_dependency, db: db_dependency):
async def product(user: product_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication failed')
    return {"User": user}



