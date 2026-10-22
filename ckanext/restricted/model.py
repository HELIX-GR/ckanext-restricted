# -*- coding: utf-8 -*-
import datetime
import logging

from sqlalchemy import Column, String, UnicodeText, DateTime
from sqlalchemy.ext.declarative import declarative_base

import ckan.model as model
from ckan.model import meta, Session

log = logging.getLogger(__name__)

# Bind declarative base to CKAN's metadata 
Base = declarative_base(metadata=meta.metadata)


class RestrictedRequest(Base):
    """
    ORM model for restricted download requests.
    """
    __tablename__ = 'restricted_requests'

    request_id = Column(String, primary_key=True, default=model.types.make_uuid)
    request_email = Column(String)

    user_id = Column(String)
    resource_id = Column(String, nullable=False)
    owner_id = Column(UnicodeText, nullable=False)

    download_id = Column(String)
    message = Column(String)

    submitted_at = Column(DateTime, default=datetime.datetime.utcnow)
    accepted_at = Column(DateTime)
    rejected_at = Column(DateTime)


def setup():
    """
    Ensure tables exist.
    NOTE: For production you should prefer Alembic migrations, but this is a
    practical compatibility approach for older extensions.
    """
    create_table()


def create_table():
    """
    Create restricted_requests table if it doesn't exist.
    """
    if model.user_table.exists(bind=meta.engine):
        Base.metadata.create_all(bind=meta.engine, tables=[RestrictedRequest.__table__])
        log.info("Table `restricted_requests` ensured (create_all checkfirst)")


def truncate_table():
    """
    Delete all rows from restricted_requests.
    """
    Session.query(RestrictedRequest).delete(synchronize_session=False)
    Session.commit()
    log.info("Table `restricted_requests` truncated (all rows deleted)")


def drop_table():
    """
    Drop restricted_requests table.
    """
    RestrictedRequest.__table__.drop(bind=meta.engine, checkfirst=True)
    Session.commit()
    log.info("Table `restricted_requests` dropped")
