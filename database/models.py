from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    TIMESTAMP,
    CheckConstraint,
    Boolean,
    Date
)

from datetime import datetime

from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Audit(Base):
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    url = Column(Text, nullable=False)
    html = Column(Text)
    scor = Column(Integer)
    device = Column(Integer, CheckConstraint("device IN (1, 2)"))
    date = Column(TIMESTAMP, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(150), unique=True, nullable=False)
    password = Column(String, nullable=False)
    admin = Column(Boolean, nullable=False, default=False)



class Lead(Base):
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, index=True)
    website = Column(Text)
    date = Column(Date)
    company_name = Column(Text)