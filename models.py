from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    fullname = Column(String)
    email = Column(String, unique=True, index=True)
    mobile = Column(String, unique=True, index=True)
    address = Column(String)
    two_step_verification = Column(Boolean, default=False)
    created_by = Column(Integer, ForeignKey("users.id")) 
    created_at = Column(DateTime)
    password = Column(String)  
    otp = Column(String, nullable=True) 
    otp_expiry = Column(DateTime, nullable=True) 

