import datetime
import uuid
from sqlalchemy import Column, DateTime, String
from app.database import Base

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

class TimestampMixin:
    """Mixin that adds created_at and updated_at timestamps to models."""
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

def generate_uuid() -> str:
    return str(uuid.uuid4())
