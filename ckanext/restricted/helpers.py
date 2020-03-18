# coding: utf8 
import logging
import ckan.logic as logic
import ckan.model as model
from ckan.common import _, c
import ckanext.restricted.model as ext_model
import ckanext.restricted.logic as ext_logic

from ckan.logic import get_action
import ckan.lib.helpers as h

logger = logging.getLogger(__name__)

def restricted_get_user_id():
    return (str(c.user))
    
def get_restricted_requests(owner_id, category):
    
    return ext_logic.get_restricted_requests(owner_id, category)
