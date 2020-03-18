
import sqlalchemy.orm as orm
import sqlalchemy.types as types
import ckan.model as model
from ckan.model.domain_object import DomainObject
from ckan.model import meta, extension
import datetime

from sqlalchemy.schema import Table, Column, ForeignKey, CreateTable, Index

import logging

logger = logging.getLogger(__name__)

restricted_requests_table = None


def setup():
    '''Define and create table (if needed)'''
    if restricted_requests_table is None:
        define_table()
        logger.debug('Table `restricted_requests` is defined in ORM mapper')
    create_table()


class RestrictedRequest(DomainObject):
    '''The ORM entity that represents a restricted request'''

    #def __init__(self, resource_id, owner_id, message):
    #    #self.request_id = request_id
    #    self.resource_id = resource_id
    #    self.owner_id = owner_id
    #    self.message = message

def define_table():
    global restricted_requests_table
    restricted_requests_table = Table('restricted_requests', meta.metadata,
        Column('request_id', types.String, primary_key=True, default=model.types.make_uuid),
        Column('request_email', types.String),
        Column('user_id', types.String), 
        Column('resource_id', types.String, nullable=False), 
        Column('owner_id', types.UnicodeText, nullable=False), 
        Column('download_id', types.String), 
        Column('message', types.String), 
        Column('submitted_at', types.DateTime, default=datetime.datetime.now()),
        Column('accepted_at', types.DateTime),
        Column('rejected_at', types.DateTime) 
    )
    orm.mapper(RestrictedRequest, restricted_requests_table, extension=[extension.PluginMapperExtension(), ])


def create_table():
    '''Create restricted_requests table'''
    if model.user_table.exists() and not restricted_requests_table.exists():
        restricted_requests_table.create()
        logger.info('Table `restricted_requests` created')


def truncate_table():
    '''Truncate restricted_requests table'''
    if restricted_requests_table.exists():
        restricted_requests_table.delete()
        logger.info('Table `restricted_requests` is truncated')


def drop_table():
    '''Drop restricted_requests table'''
    if restricted_requests_table.exists():
        restricted_requests_table.drop()
        logger.info('Table `restricted_requests` is dropped')
