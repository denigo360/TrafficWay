import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

is_production = os.environ.get('TRAFFICWAY_PRODUCTION') is not None
if is_production:
    postgres_user = os.environ['POSTGRES_USER']
    postgres_password = os.environ['POSTGRES_PASSWORD']
    postgres_database = os.environ['POSTGRES_DB']
    SQLALCHEMY_DATABASE_URL = f"postgresql://{postgres_user}:{postgres_password}@db:5432/{postgres_database}"
else:
    SQLALCHEMY_DATABASE_URL = "sqlite///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
