from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

# Using SQLite for local CachyOS prototyping convenience, easily swappable to PostgreSQL URL
DATABASE_URL = "sqlite:///./sentinel.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DBAlert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    src_ip = Column(String, index=True)
    dest_ip = Column(String)
    severity = Column(Integer)
    signature = Column(Text)
    tactic = Column(String)
    technique_id = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)
