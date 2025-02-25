from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import pandas as pd
from typing import List, Optional
import secrets
from database import get_db, Base, engine 
from models import User

api = FastAPI()

SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") 

def get_hashed_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user

@api.post("/signup")
async def signup(user_data: dict, db: Session = Depends(get_db)):
    print(f"Signup request received: {user_data}") 
    required_fields = ["fullname", "email", "mobile", "address", "two_step_verification", "password"] 
    if not all(field in user_data for field in required_fields):
        print("Missing required fields")
        raise HTTPException(status_code=400, detail="Missing required fields")

    existing_email_user = db.query(User).filter(User.email == user_data["email"]).first()
    print(f"Existing email user: {existing_email_user}")
    if existing_email_user:
        print("Email already registered")
        raise HTTPException(status_code=400, detail="Email already registered")

    existing_mobile_user = db.query(User).filter(User.mobile == str(user_data["mobile"])).first()
    print(f"Existing mobile user: {existing_mobile_user}")
    if existing_mobile_user:
        print("Mobile number already registered")
        raise HTTPException(status_code=400, detail="Mobile number already registered")

    hashed_password = get_hashed_password(user_data["password"])
    print(f"Hashed password: {hashed_password}")
    created_by_id = user_data.get("created_by_id")
    print(f"Created by ID: {created_by_id}")

    new_user = User(
        fullname=user_data["fullname"],
        email=user_data["email"],
        mobile=user_data["mobile"],
        address=user_data["address"],
        two_step_verification=bool(user_data["two_step_verification"]),
        created_by=created_by_id, 
        created_at=datetime.now().strftime("%d-%m-%Y %H:%M"),
        password=hashed_password,
    )
    print(f"New user object: {new_user}")
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print(f"User created successfully. User ID: {new_user.id}")
        return {"message": "User created successfully", "user_id": new_user.id}
    except Exception as e:
        print(f"Error during database operation: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


@api.post("/signin")
async def signin(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter((User.email == form_data.username) | (User.mobile == str(form_data.username))).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email/mobile or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.two_step_verification:
        # Generate and store OTP
        otp = secrets.randbelow(1000000)
        user.otp = str(otp).zfill(6) 
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        db.commit()
        return {"message": "OTP sent for verification", "user_id": user.id} 
    else:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires 
        )
        return {"access_token": access_token, "token_type": "bearer", "user": user}
        
@api.post("/verify-otp")
async def verify_otp(request_data: dict, db: Session = Depends(get_db)):
    user_id = request_data.get("user_id")
    otp = request_data.get("otp")

    if not user_id or not otp:
        raise HTTPException(status_code=400, detail="Missing user_id or otp")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.otp != otp or user.otp_expiry < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    user.otp = None
    user.otp_expiry = None
    db.commit()

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user": user}



@api.get("/users", response_model=List[dict])
async def get_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).all()
    all_users = db.query(User).all()
    user_map = {user.id: user for user in all_users}

    result = []
    for user in users:
        user_data = user.__dict__.copy()  
        user_data.pop('_sa_instance_state', None)
        user_data.pop('password', None) 
        user_data.pop('otp', None)
        user_data.pop('otp_expiry', None)

        created_by_id = user_data.get('created_by')
        if created_by_id and created_by_id in user_map:
            created_by_user = user_map[created_by_id].__dict__.copy()
            created_by_user.pop('_sa_instance_state', None)
            created_by_user.pop('password', None)
            created_by_user.pop('otp', None)
            created_by_user.pop('otp_expiry', None)
            user_data['created_by_user'] = created_by_user
        else:
            user_data['created_by_user'] = None

        result.append(user_data)

    return result


@api.post("/upload-csv")
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only CSV files are allowed.")

    try:
        df = pd.read_csv(file.file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading CSV file: {e}")
    df = df.dropna() 
    def process_csv(df: pd.DataFrame, db: Session):

        data = df.to_dict(orient="records")

        for row in data:
            try:
                new_user = User(
                    fullname=row.get("fullname"),
                    email=row.get("email"),
                    mobile=row.get("mobile"),
                    address=row.get("address"),
                    two_step_verification=bool(row.get("two_step_verification", 0)), 
                    created_by=row.get("created_by"),
                    created_at=datetime.now().strftime("%d-%m-%Y %H:%M"),
                    password=get_hashed_password(row.get("password", "defaultpassword")),
                )
                db.add(new_user)
            except Exception as e:
                print(f"Error processing row: {row}, Error: {e}")
                continue 

        db.commit() 
        print("CSV processing completed")

    import threading
    thread = threading.Thread(target=process_csv, args=(df, db))
    thread.start()

    return {"message": "CSV upload started. Processing in background."}



@api.get("/search")
async def search(
    name: Optional[str] = None,
    account_no: Optional[str] = None,
    mobile_no: Optional[str] = None,
    email: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(User)

    if name:
        query = query.filter(User.fullname.ilike(f"%{name}%"))
    if account_no:
        query = query.filter(User.id == account_no)  
    if mobile_no:
        query = query.filter(User.mobile.ilike(f"%{mobile_no}%"))
    if email:
        query = query.filter(User.email.ilike(f"%{email}%"))

    results = query.all()
    formatted_results = []
    for user in results:
        user_data = user.__dict__.copy()
        user_data.pop('_sa_instance_state', None)
        user_data.pop('password', None)
        user_data.pop('otp', None)
        user_data.pop('otp_expiry', None)
        formatted_results.append(user_data)

    return formatted_results


def create_tables():
    try:
        Base.metadata.create_all(bind=engine)
        print("Tables created successfully.")
    except Exception as e:
        print(f"Error creating tables: {e}")

if __name__ == "__main__":
    import uvicorn
    create_tables() 
    uvicorn.run(api)
