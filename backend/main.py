from fastapi import FastAPI, HTTPException
from passlib.context import CryptContext
import models # Import the models we just created

# --- Security Setup ---
# We specify the hashing algorithm we want to use
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Application Setup ---
app = FastAPI()

# This is a temporary, in-memory "database"
# It's just a list that will reset every time the app restarts.
fake_users_db = []

# --- Utility Functions ---
def get_password_hash(password):
    return pwd_context.hash(password)

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Hello from the Uni-Share Platform API"}

@app.post("/users/", response_model=models.User)
def create_user(user: models.UserCreate):
    # Check if user already exists
    for db_user in fake_users_db:
        if db_user["email"] == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")

    # Hash the password before storing
    hashed_password = get_password_hash(user.password)

    # Create a new user object (as a dictionary for our fake db)
    # Note: In a real DB, this would be an object with an auto-incrementing ID
    new_user = {
        "id": len(fake_users_db) + 1,
        "email": user.email,
        "hashed_password": hashed_password
    }

    # "Save" the user to our fake database
    fake_users_db.append(new_user)
    
    # Return the new user's data (without the password)
    return new_user