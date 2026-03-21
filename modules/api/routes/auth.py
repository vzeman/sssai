from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from modules.api.database import get_db
from modules.api.models import User
from modules.api.schemas import UserCreate, UserResponse, Token
from modules.api.auth import hash_password, verify_password, create_access_token

router = APIRouter()


@router.post("/register", response_model=UserResponse)
def register(body: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=body.email, hashed_password=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(body: UserCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return Token(access_token=create_access_token(user.id))
