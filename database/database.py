from typing import Optional

from sqlalchemy import (
    create_engine,
    TIMESTAMP,
    select
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from .models import Audit, User, Lead
from .utils import hash_password,verify_password

class AuditDatabase:
    def __init__(self, database_url: str):
        self.engine = create_engine(database_url, future=True)
        self.Session = sessionmaker(bind=self.engine, future=True)

    def insert_audit(
        self,
        ip: str,
        url: str,
        html: Optional[str] = None,
        scor: Optional[int] = None,
        device: Optional[int] = None,
    ):
        try:
            with self.Session() as session:
                audit = Audit(
                    ip=ip,
                    url=url,
                    html=html,
                    scor=scor,
                    device=device,
                )
                session.add(audit)
                session.commit()
                session.refresh(audit)

                return {
                    "status": 200,
                    "message": "Audit inserted successfully",
                    "data": {"id": audit.id},
                }

        except Exception:
            return {
                "status": 500,
                "message": "Server error",
            }

    def get_audits(
        self,
        id: Optional[int] = None,
        ip: Optional[str] = None,
        url: Optional[str] = None,
        html: Optional[str] = None,
        scor: Optional[int] = None,
        device: Optional[int] = None,
        date: Optional[str] = None,
    ):
        try:
            with self.Session() as session:
                stmt = select(Audit)

                if id is not None:
                    stmt = stmt.where(Audit.id == id)

                if ip is not None:
                    stmt = stmt.where(Audit.ip == ip)

                if url is not None:
                    stmt = stmt.where(Audit.url == url)

                if html is not None:
                    stmt = stmt.where(Audit.html == html)

                if scor is not None:
                    stmt = stmt.where(Audit.scor == scor)

                if device is not None:
                    stmt = stmt.where(Audit.device == device)

                if date is not None:
                    stmt = stmt.where(Audit.date.cast(TIMESTAMP).date() == date)

                results = session.execute(stmt).scalars().all()

                if not results:
                    return {
                        "status": 404,
                        "message": "No audits found",
                    }

                data = [
                    {
                        "id": a.id,
                        "ip": a.ip,
                        "url": a.url,
                        "html": a.html,
                        "scor": a.scor,
                        "device": a.device,
                        "date": a.date.isoformat(),
                    }
                    for a in results
                ]

                return {
                    "status": 200,
                    "message": "Success",
                    "data": data,
                }

        except Exception:
            return {
                "status": 500,
                "message": "Server error",
            }

    def create_user(self, username: str, password: str, admin: bool = False):
        try:
            with self.Session() as session:
                user = User(
                    username=username,
                    password=hash_password(password),
                    admin=admin
                )
                session.add(user)
                session.commit()

                return {
                    "status": 200,
                    "message": "User created successfully",
                }

        except IntegrityError:
            return {
                "status": 400,
                "message": "Username already exists",
            }

        except Exception:
            return {
                "status": 500,
                "message": "Server error",
            }

    def insert_lead(
            self,
            website: str,
            date,
            company_name: str,
    ):
        try:
            with self.Session() as session:
                lead = Lead(
                    website=website,
                    date=date,
                    company_name=company_name,
                )
                session.add(lead)
                session.commit()
                session.refresh(lead)

                return {
                    "status": 200,
                    "message": "Lead inserted successfully",
                    "data": {"id": lead.id},
                }

        except Exception as error:
            print(error)
            return {
                "status": 500,
                "message": "Server error",
            }

    def authenticate(self, username: str, password: str):
        try:
            with self.Session() as session:
                stmt = select(User).where(User.username == username)
                user = session.execute(stmt).scalar_one_or_none()

                if not user:
                    return {
                        "status": 404,
                        "message": "User not found",
                    }

                if not verify_password(password, user.password):
                    return {
                        "status": 401,
                        "message": "Invalid credentials",
                    }

                return {
                    "status": 200,
                    "message": "Authenticated",
                    "data": {
                        "id": user.id,
                        "username": user.username,
                        "admin": user.admin,
                    },
                }

        except Exception:
            return {
                "status": 500,
                "message": "Server error",
            }