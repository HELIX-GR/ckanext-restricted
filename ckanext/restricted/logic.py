# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _, c

from ckan.lib.base import render_jinja2
import ckan.lib.mailer as mailer
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import json
import ckan.model as model
import ckanext.restricted.model as ext_model

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger

log = getLogger(__name__)


def restricted_get_username_from_context(context):
    auth_user_obj = context.get('auth_user_obj', None)
    user_name = ''
    if auth_user_obj:
        user_name = auth_user_obj.as_dict().get('name', '')
    else:
        if authz.get_user_id_for_username(context.get('user'), allow_none=True):
            user_name = context.get('user', '')
    return user_name


def restricted_get_restricted_dict(resource_dict):
    restricted_dict = {'level': 'public', 'allowed_users': []}
    # the ckan plugins ckanext-scheming and ckanext-composite
    # change the structure of the resource dict and the nature of how
    # to access our restricted field values
    if resource_dict:
        # the dict might exist as a child inside the extras dict
        extras = resource_dict.get('extras', {})
        # or the dict might exist as a direct descendant of the resource dict
        restricted = resource_dict.get('restricted', extras.get('restricted', {}))
        if not isinstance(restricted, dict):
            # if the restricted property does exist, but not as a dict,
            # we may need to parse it as a JSON string to gain access to the values.
            # as is the case when making composite fields
            try:
                restricted = json.loads(restricted)
            except ValueError:
                restricted = {}
        if restricted:
            #restricted_level = restricted.get('level', 'public')
            #allowed_users = restricted.get('allowed_users', '')
            restricted_level = 'only_allowed_users'
            # get allowed users from new field 'allowed users' instead of nested restricted field
            allowed_users = resource_dict.get('allowed_users', '')
            if not isinstance(allowed_users, list):
                allowed_users = allowed_users.split(',')
            restricted_dict = {
                'level': restricted_level,
                'allowed_users': allowed_users}
    return restricted_dict


def restricted_check_user_resource_access(user, resource_dict, package_dict):
    restricted_dict = restricted_get_restricted_dict(resource_dict)
    restricted_level = restricted_dict.get('level', 'public')
    allowed_users = restricted_dict.get('allowed_users', [])
    
    # Public resources (DEFAULT)
    if not restricted_level or restricted_level == 'public':
        return {'success': True}

    # Registered user
    if not user:
        return {
            'success': False,
            'msg': 'Resource access restricted to registered users'}
    else:
        if restricted_level == 'registered' or not restricted_level:
            return {'success': True}

    # Since we have a user, check if it is in the allowed list
    if user in allowed_users:
        return {'success': True}
    elif restricted_level == 'only_allowed_users':
        return {
            'success': False,
            'msg': 'Resource access restricted to allowed users only'}

    # Get organization list
    user_organization_dict = {}

    context = {'user': user}
    data_dict = {'permission': 'read'}

    for org in logic.get_action('organization_list_for_user')(context, data_dict):
        name = org.get('name', '')
        id = org.get('id', '')
        if name and id:
            user_organization_dict[id] = name

    # Any Organization Members (Trusted Users)
    if not user_organization_dict:
        return {
            'success': False,
            'msg': 'Resource access restricted to members of an organization'}

    if restricted_level == 'any_organization':
        return {'success': True}

    pkg_organization_id = package_dict.get('owner_org', '')

    # Same Organization Members
    if restricted_level == 'same_organization':
        if pkg_organization_id in user_organization_dict.keys():
            return {'success': True}

    return {
        'success': False,
        'msg': ('Resource access restricted to same '
                'organization ({}) members').format(pkg_organization_id)}

def restricted_mail_allowed_user(user_id, resource):
    log.debug('restricted_mail_allowed_user: Notifying "{}"'.format(user_id))
    try:
        # Get user information
        context = {}
        context['ignore_auth'] = True
        context['keep_email'] = True
        user = toolkit.get_action('user_show')(context, {'id': user_id})
        user_email = user['email']
        user_name = user.get('display_name', user['name'])
        resource_name = resource.get('name', resource['id'])

        # maybe check user[activity_streams_email_notifications]==True

        mail_body = restricted_allowed_user_mail_body(resource, user)
        mail_subject = _('Αποδοχή αιτήματος πρόσβασης στον πόρο {}').format(resource_name)

        # Send mail to user
        mailer.mail_recipient(user_name, user_email, mail_subject, mail_body)

        # Send copy to admin (temporarily disabled)
        #mailer.mail_recipient(
        #    'CKAN Admin', config.get('email_to'),
        #    'Fwd: {}'.format(mail_subject), mail_body)

    except Exception as e:
        log.warning(('restricted_mail_allowed_user: '
                     'Failed to send mail to "{0}": {1}').format(user_id,e))


def restricted_allowed_user_mail_body(resource, user=None, download_id = None):
    if user:
        resource_link = toolkit.url_for(
            controller='package', action='resource_read',
            id=resource.get('package_id'), resource_id=resource.get('id'))
        user_name = user.get('display_name', user['name'])
    else:
        resource_link = '/helix/files/restricted_resources/' + download_id + '/download/'
        user_name = 'user'
    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_name': user_name,
        'resource_name': resource.get('name', resource['id']),
        'resource_link': config.get('ckan.site_url') + resource_link,
        'resource_url': resource.get('url')}

    return render_jinja2(
        'restricted/emails/restricted_user_allowed.txt', extra_vars)

def restricted_notify_allowed_users(previous_value, updated_resource):
    
    def _safe_json_loads(json_string, default={}):
        try:
            return json.loads(json_string)
        except Exception:
            return default

    previous_restricted = _safe_json_loads(previous_value)
    updated_restricted = _safe_json_loads(updated_resource.get('restricted', ''))
    # compare restricted users_allowed values
    #updated_allowed_users = set(updated_restricted.get('allowed_users', '').split(','))
    updated_allowed_users = updated_resource.get('allowed_users', '')

    if updated_allowed_users:  
        # convert to list
        if not isinstance(previous_value, list):
            previous_value = previous_value.split(',')
        if not isinstance(updated_allowed_users, list):
            updated_allowed_users = updated_allowed_users.split(',')
            previous_allowed_users = previous_value
            #previous_allowed_users = previous_restricted.get('allowed_users', '').split(',')
            for user_id in updated_allowed_users:
                if user_id not in previous_allowed_users:
                    restricted_mail_allowed_user(user_id, updated_resource)


def get_restricted_requests(owner_id, category):
    result = []
    context = {'model': model, 'session': model.Session, 'user': c.user}
    download_id = ext_model.RestrictedRequest.download_id
    if category == 'registered':
        requests = model.Session.query(ext_model.RestrictedRequest).filter_by(
            owner_id=owner_id, request_email=None, download_id=None)
    elif category == 'unregistered':
        requests = model.Session.query(ext_model.RestrictedRequest).filter_by(
            owner_id=owner_id, user_id=None, download_id=None)
    elif category == 'accepted':
        requests = model.Session.query(
            ext_model.RestrictedRequest).filter_by(owner_id=owner_id,rejected_at=None).filter(download_id!=None)
    for request in requests:
        resource = logic.get_action('resource_show')(
            context, {'id': request.resource_id})
        result.append({
            'resource_name': resource['name'],
            'resource_id': resource['id'],
            'package_id': resource['package_id'],
            'request_id': request.request_id,
            'user_id': request.user_id,
            'download_id': request.download_id,
            'message': request.message,
            'request_email': request.request_email,
            'state': 'true' if request.download_id else 'false'
        })
    return result

def save_restricted_request(request_dict):
    # Add record
    request = ext_model.RestrictedRequest()
    model.Session.add(request)
    
    request.resource_id = request_dict.get('resource_id')
    request.owner_id = request_dict.get('owner_id')
    request.message = request_dict.get('message')
    request.user_id = request_dict.get('user_id')
    request.request_email = request_dict.get('request_email')
    #request.submitted_at = request_dict.get('submitted_at')
    model.Session.commit()


def update_restricted_request(request_dict):
    request = model.Session.query(ext_model.RestrictedRequest).filter_by(
        request_id=str(request_dict.get('request_id'))).one_or_none()
    if request:
        # Update record
        request.download_id = request_dict.get('download_id', request.download_id )
        request.accepted_at = request_dict.get('accepted_at', request.accepted_at)
        request.rejected_at = request_dict.get('rejected_at', request.rejected_at)
    model.Session.commit()
    
