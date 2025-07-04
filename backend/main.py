from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel, EmailStr
from typing import List, Optional # Import Optional
import models

# --- Security Setup ---
SECRET_KEY = "a_super_secret_key_change_this_later"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Application Setup ---
app = FastAPI()

# --- Temporary In-Memory "Databases" ---
fake_users_db = []
fake_listings_db = []

# --- Pydantic Models for Token ---
class TokenData(BaseModel):
    email: EmailStr | None = None

# --- Utility Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(email: str):
    for user in fake_users_db:
        if user["email"] == email:
            return user
    return None

# --- Dependency for getting current user ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Hello from the Uni-Share Platform API"}

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=models.User)
def read_users_me(current_user: dict = Depends(get_current_user)):
    return models.User.from_attributes(current_user)

@app.post("/users/", response_model=models.User)
def create_user(user: models.UserCreate):
    db_user = get_user(user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = {
        "id": len(fake_users_db) + 1,
        "email": user.email,
        "hashed_password": hashed_password
    }
    fake_users_db.append(new_user)
    return new_user

@app.post("/listings/", response_model=models.Listing)
def create_listing(
    listing: models.ListingCreate,
    current_user: dict = Depends(get_current_user)
):
    listing_data = listing.dict()
    listing_data["id"] = len(fake_listings_db) + 1
    listing_data["owner_id"] = current_user["id"]
    fake_listings_db.append(listing_data)
    return listing_data

# --- MODIFIED ENDPOINT TO VIEW LISTINGS WITH FILTERING ---
@app.get("/listings/", response_model=List[models.Listing])
def read_listings(category: Optional[models.Category] = None):
    if category:
        # Return only listings that match the category
        return [
            listing for listing in fake_listings_db if listing["category"] == category
        ]
    # Return all listings if no category is provided
    return fake_listings_db