from pydantic import BaseModel, EmailStr
from enum import Enum # Import Enum

# --- Category Enum ---
class Category(str, Enum):
    microscopy = "Microscopy & Imaging"
    spectroscopy = "Spectroscopy & Spectrometry"
    genomics = "Genomics & Sequencing"
    automation = "Lab Automation & Robotics"
    manufacturing = "Manufacturing & Prototyping"
    analytical = "Analytical & Testing"
    computing = "IT & High-Performance Computing"
    other = "Other"


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
    # Add the new category field
    category: Category
    technical_specifications: str | None = None
    price_per_hour: float
    price_per_day: float

class Listing(ListingCreate):
    id: int
    owner_id: int
    
    class Config:
        from_attributes = True