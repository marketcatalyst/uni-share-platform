from pydantic import BaseModel, EmailStr

# --- User Models ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True

# --- Listing Models ---
class ListingCreate(BaseModel):
    title: str
    description: str | None = None
    technical_specifications: str | None = None
    price_per_hour: float
    price_per_day: float

class Listing(ListingCreate):
    id: int
    owner_id: int
    
    class Config:
        from_attributes = True
