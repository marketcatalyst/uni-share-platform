from pydantic import BaseModel, EmailStr

# What the user sends to us when creating an account
class UserCreate(BaseModel):
    email: EmailStr
    password: str

# What we send back to the user (notice no password)
class User(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True
        