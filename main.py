from fastapi import FastAPI, status, Depends, HTTPException
import models
from database import engine, SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
import uvicorn
import auth
import product
from auth import get_current_user
from product import get_current_products


app = FastAPI(
    title="API",
    swagger_ui_parameters={"defaultModelsExpandDepth": -1}
)

app.include_router(auth.router)
app.include_router(product.router)

models.Base.metadata.create_all(bind=engine)

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     finally:
#         db.close()

# db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

@app.get("/", status_code=status.HTTP_200_OK, tags=['User'])
# async def user(user: user_dependency, db: db_dependency):
async def user(user: user_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication failed')
    return {"User": user}
