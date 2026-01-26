import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import timedelta
from app.core.security import verify_password, create_access_token, get_password_hash
from app.core.config import settings
from app.api import deps
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, Token

router = APIRouter()


@router.post("/signup", response_model=UserResponse)
async def create_user(
        user_in: UserCreate,
        db: AsyncSession = Depends(deps.get_db)
):
    result = await db.execute(select(User).where(User.email == user_in.email))
    user = result.scalars().first()

    if user:
        raise HTTPException(
            status_code=400,
            detail="Bu email adresi zaten kullanımda."
        )

    generated_api_key = f"sk_live_{secrets.token_urlsafe(32)}"

    hashed_password = get_password_hash(user_in.password)

    new_user = User(
        email=user_in.email,
        hashed_password=hashed_password,
        full_name=user_in.full_name,
        is_active=True,
        api_key=generated_api_key
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token)
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: AsyncSession = Depends(deps.get_db)
):
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email veya şifre hatalı",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}