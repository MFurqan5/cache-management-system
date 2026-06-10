# backend/routes/auth.py
"""Authentication endpoints for SENTINELCACHE AI
   User storage: PostgreSQL (primary) with SQLite fallback.
"""
import os
import logging
import re
from datetime import datetime, timedelta
from typing import Optional
import jwt
import bcrypt
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from backend.database import db

logger = logging.getLogger(__name__)

# Authentication Configuration
SECRET_KEY = os.getenv("JWT_SECRET", os.getenv("APP_SECRET_KEY", "sentinelcache-ai-super-secret-key-change-in-prod-2026"))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60  # 24 hours

router = APIRouter(prefix="/auth", tags=["auth"])

# Password hashing utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification failed: {e}")
        return False

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Token utility
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Pydantic Schemas
class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = v.strip().lower()
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, v):
            raise ValueError('Invalid email format')
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain alphanumeric characters, underscores, or hyphens')
        return v

class UserLoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)

class UserUpdateRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[str] = Field(None, min_length=3, max_length=100)
    password: Optional[str] = Field(None, min_length=6, max_length=100)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is None:
            return v
        v = v.strip().lower()
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, v):
            raise ValueError('Invalid email format')
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if v is None:
            return v
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain alphanumeric characters, underscores, or hyphens')
        return v

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

class MessageResponse(BaseModel):
    message: str

# ─── Auth dependency ────────────────────────────────────────────────────────────
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends

security = HTTPBearer()

def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except Exception as e:
        logger.warning(f"Invalid token: {e}")
        return None

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    user_id = decode_token(token)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"id": user_id}

# ─── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegisterRequest):
    """Register a new user — stored in PostgreSQL (SQLite fallback if PostgreSQL unavailable)"""
    username = user_data.username
    email = user_data.email
    password = user_data.password

    # Check uniqueness
    try:
        if db.get_user_by_username(username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already registered"
            )
        if db.get_user_by_email(email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already registered"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking user existence for {username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during registration"
        )

    # Hash and persist
    password_hash = get_password_hash(password)
    try:
        db.create_user(username, email, password_hash)
        logger.info(f"Successfully registered user: {username}")
        return {"message": "User registered successfully"}
    except Exception as e:
        logger.error(f"Error during registration for {username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user due to a database error"
        )


@router.post("/login", response_model=TokenResponse)
async def login(login_data: UserLoginRequest):
    """Authenticate a user — checks PostgreSQL (SQLite fallback if PostgreSQL unavailable)"""
    input_identifier = login_data.username_or_email.strip()
    password = login_data.password

    user = None
    try:
        if "@" in input_identifier:
            user = db.get_user_by_email(input_identifier.lower())
        if not user:
            user = db.get_user_by_username(input_identifier)
        if not user and "@" not in input_identifier:
            user = db.get_user_by_email(input_identifier.lower())
    except Exception as e:
        logger.error(f"Database error during login lookup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during authentication"
        )

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = {
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"]
    }
    access_token = create_access_token(data=token_data)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user.get("role", "user")
        }
    }


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current logged-in user profile from PostgreSQL"""
    user_id = current_user.get("id")
    try:
        conn = db.ml_integration.get_postgres_connection()
        import psycopg2.extras
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = %s::uuid",
            (user_id,)
        )
        row = cur.fetchone()
        cur.close()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return {
            "id": str(row["id"]),
            "username": row["username"],
            "email": row["email"],
            "role": row.get("role", "user"),
            "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"get_me failed for user {user_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to fetch user profile")


@router.put("/me")
async def update_me(update_data: UserUpdateRequest, current_user: dict = Depends(get_current_user)):
    """Update current user's profile in PostgreSQL (username, email, and/or password)"""
    user_id = current_user.get("id")

    # Build SET clause dynamically — only update provided fields
    fields = {}
    if update_data.username is not None:
        fields["username"] = update_data.username
    if update_data.email is not None:
        fields["email"] = update_data.email.lower()
    if update_data.password is not None:
        fields["password_hash"] = get_password_hash(update_data.password)

    if not fields:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields provided to update")

    try:
        conn = db.ml_integration.get_postgres_connection()
        import psycopg2.extras
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        # Check uniqueness for username/email changes
        if "username" in fields:
            cur.execute("SELECT id FROM users WHERE username = %s AND id != %s::uuid", (fields["username"], user_id))
            if cur.fetchone():
                cur.close()
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
        if "email" in fields:
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s::uuid", (fields["email"], user_id))
            if cur.fetchone():
                cur.close()
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

        set_clause = ", ".join(f"{col} = %s" for col in fields)
        values = list(fields.values()) + [user_id]
        cur.execute(
            f"UPDATE users SET {set_clause} WHERE id = %s::uuid RETURNING id, username, email, role",
            values
        )
        updated = cur.fetchone()
        conn.commit()
        cur.close()

        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        logger.info(f"User {user_id} profile updated in PostgreSQL")
        return {
            "message": "Profile updated successfully",
            "user": {
                "id": str(updated["id"]),
                "username": updated["username"],
                "email": updated["email"],
                "role": updated.get("role", "user"),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"update_me failed for user {user_id}: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update profile")
