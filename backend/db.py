import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://siem:siem@db:5432/siem")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ParsedRule(Base):
    __tablename__ = "parsed_rules"
    id = Column(Integer, primary_key=True)
    rule_id = Column(String, unique=True, index=True)
    name = Column(String)
    rule_type = Column(String)  # 'star' or 'sigma'
    fields_used = Column(JSONB)
    raw = Column(Text)
    cached_at = Column(DateTime, default=datetime.utcnow)


class ParserField(Base):
    __tablename__ = "parser_fields"
    id = Column(Integer, primary_key=True)
    parser_name = Column(String, index=True)
    field_name = Column(String)
    field_type = Column(String)


class ActiveSource(Base):
    __tablename__ = "active_sources"
    id = Column(Integer, primary_key=True)
    source_name = Column(String, unique=True, index=True)
    event_count = Column(Integer, default=0)
    synced_at = Column(DateTime, default=datetime.utcnow)


class IngestSnapshot(Base):
    __tablename__ = "ingest_snapshots"
    id = Column(Integer, primary_key=True)
    period_days = Column(Integer)
    data = Column(JSONB)
    recorded_at = Column(DateTime, default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
