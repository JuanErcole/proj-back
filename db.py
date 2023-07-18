from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from config.prod import URL_DATABASE 
from fastapi import Depends
from sqlalchemy.orm.session import Session
from typing import Annotated

engine = create_engine(URL_DATABASE)

session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()

def create_tables():
  Base.metadata.create_all(bind=engine)

def get_db() :
  db = session_local()
  try: 
    yield db
    db.commit()
  finally:
    db.close()
