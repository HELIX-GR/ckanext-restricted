# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _, c

import ckan.plugins.toolkit as tk
import ckan.lib.mailer as mailer
import ckan.lib.search as search
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import base64
import datetime
import os
import json
import ckan.model as model
from sqlalchemy import or_
import ckanext.restricted.model as ext_model

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger

log = getLogger(__name__)


def email_site_title():
    """Site name used in emails (instead of ckan.site_title, which is "CKAN")."""
    return config.get('ckanext.restricted.email_site_title', 'HEAL-Link')


def send_mail(recipient_name, recipient_email, subject, body, body_html=None, headers=None):
    """ckan.lib.mailer.mail_recipient, but with our own sender name in the From header.

    The public mail_recipient always uses ckan.site_title as sender name.
    """
    mailer._mail_recipient(
        recipient_name, recipient_email, email_site_title(), config.get('ckan.site_url'),
        subject, body, body_html=body_html, headers=headers)


def restricted_get_username_from_context(context):
    auth_user_obj = context.get('auth_user_obj', None)
    user_name = ''
    if auth_user_obj:
        # flask-login's AnonymousUser has no name
        user_name = getattr(auth_user_obj, 'name', '') or ''
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
        #if not isinstance(restricted, dict):
            # if the restricted property does exist, but not as a dict,
            # we may need to parse it as a JSON string to gain access to the values.
            # as is the case when making composite fields
            # try:
            #     restricted = json.loads(restricted)
            # except ValueError:
            #     restricted = {}
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
    log.info('restricted_mail_allowed_user: Notifying "{}"'.format(user_id))
    try:
        # Get user information
        context = {}
        context['ignore_auth'] = True
        context['keep_email'] = True
        user = toolkit.get_action('user_show')(context, {'id': user_id})
        user_email = user['email']
        user_name = user.get('name', user['name'])
        resource_name = resource.get('name', resource['id'])

        # maybe check user[activity_streams_email_notifications]==True

        mail_body = restricted_allowed_user_mail_body(resource, user)
        mail_subject = _('Αποδοχή αιτήματος πρόσβασης στον πόρο {}').format(resource_name)

        # Send mail to user
        send_mail(user_name, user_email, mail_subject, mail_body)

        # Send copy to admin (temporarily disabled)
        #mailer.mail_recipient(
        #    'CKAN Admin', config.get('email_to'),
        #    'Fwd: {}'.format(mail_subject), mail_body)

    except Exception as e:
        log.warning(('restricted_mail_allowed_user: '
                     'Failed to send mail to "{0}": {1}').format(user_id,e))


def restricted_allowed_user_mail_body(resource, user=None, download_id = None):
    if user:
        if resource.get('url_type') == 'upload':
            # uploaded file: our own route forces a download (CKAN's would open it in the browser)
            resource_link = toolkit.url_for('restricted.download_resource_as_user', resource_id=resource.get('id'))
        else:
            resource_link = toolkit.url_for(
                'dataset_resource.read',
                id=resource.get('package_id'), resource_id=resource.get('id'))
        user_name = user.get('name')
    else:
        resource_link = toolkit.url_for('restricted.download_resource', download_id=download_id)
        user_name = 'user'
    extra_vars = {
        'site_title': email_site_title(),
        'site_url': config.get('ckan.site_url'),
        'user_name': user_name,
        'resource_name': resource.get('name', resource['id']),
        'resource_link': config.get('ckan.site_url') + resource_link,
        'resource_url': resource.get('url')}

    return tk.render(
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
    context.update({'ignore_auth': True})
    download_id = ext_model.RestrictedRequest.download_id
    if category == 'registered':
        requests = model.Session.query(ext_model.RestrictedRequest).filter_by(
            owner_id=owner_id, request_email=None, rejected_at=None, download_id=None)
    elif category == 'unregistered':
        requests = model.Session.query(ext_model.RestrictedRequest).filter_by(
            owner_id=owner_id, user_id=None, rejected_at=None,  download_id=None)
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
    request.submitted_at = request_dict.get('submitted_at')
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
    


# --- Access request management (dataset owner dashboard) ---------------------

STATUS_PENDING = 'pending'
STATUS_ACCEPTED = 'accepted'
STATUS_REJECTED = 'rejected'
STATUS_REVOKED = 'revoked'


def get_package_owner(package_dict):
    """Return the user object that manages access requests for a dataset.

    The owner is the dataset creator. When the creator is missing or is a
    sysadmin (e.g. datasets migrated by an admin whose real owner has not yet
    registered), None is returned and the caller falls back to the site admin.
    """
    creator = model.User.get(package_dict.get('creator_user_id') or '')
    if creator is None or creator.sysadmin:
        return None
    return creator


def _request_status(request):
    if request.rejected_at:
        # accepted first, then withdrawn by the owner
        return STATUS_REVOKED if request.accepted_at else STATUS_REJECTED
    if request.accepted_at:
        return STATUS_ACCEPTED
    return STATUS_PENDING


def _request_to_dict(request, resource, package):
    requester = model.User.get(request.user_id or '')
    return {
        'request_id': request.request_id,
        'resource_id': resource.id,
        'resource_name': resource.name or resource.id,
        'package_name': package.name,
        'package_title': package.title or package.name,
        'user_id': request.user_id,
        'user_display_name': requester.display_name if requester else (request.user_id or request.request_email),
        'user_email': requester.email if requester else request.request_email,
        'message': request.message,
        'submitted_at': request.submitted_at,
        'status': _request_status(request),
    }


def _requests_query():
    return (model.Session.query(ext_model.RestrictedRequest, model.Resource, model.Package)
            .join(model.Resource, model.Resource.id == ext_model.RestrictedRequest.resource_id)
            .join(model.Package, model.Package.id == model.Resource.package_id)
            .filter(model.Resource.state == 'active')
            .order_by(ext_model.RestrictedRequest.submitted_at.desc()))


def _owner_filter(user):
    """Packages whose requests `user` manages: own datasets, and for sysadmins
    also the ones without a regular-user owner (see get_package_owner)."""
    cond = model.Package.creator_user_id == user.id
    if user.sysadmin:
        sysadmin_ids = [u.id for u in model.Session.query(model.User).filter_by(sysadmin=True)]
        cond = or_(cond, model.Package.creator_user_id.in_(sysadmin_ids),
                   model.Package.creator_user_id.is_(None))
    return cond


def get_requests_for_owner(user):
    """Requests (all states) for resources in datasets managed by `user`."""
    query = _requests_query().filter(_owner_filter(user))
    return [_request_to_dict(*row) for row in query]


def get_requests_made_by(user):
    """Requests (all states) submitted by `user`."""
    query = _requests_query().filter(ext_model.RestrictedRequest.user_id == user.name)
    return [_request_to_dict(*row) for row in query]


def get_pending_request(user_name, resource_id, request_email=None):
    """Pending request of a registered user, or of an unregistered one (by email)."""
    filters = {'user_id': user_name} if user_name else {'user_id': None, 'request_email': request_email}
    return model.Session.query(ext_model.RestrictedRequest).filter_by(
        resource_id=resource_id, accepted_at=None, rejected_at=None, **filters).first()


def _get_manageable_request(request_id, acting_user):
    """Return (request, resource, package) if `acting_user` may manage it."""
    row = _requests_query().filter(
        ext_model.RestrictedRequest.request_id == request_id).filter(_owner_filter(acting_user)).first()
    if row is None:
        raise tk.ObjectNotFound(_('Request not found'))
    return row


def accept_request(request_id, acting_user):
    """Add the requester to the resource's allowed users and notify them.

    Only `allowed_users` is changed, directly on the resource, so datasets
    that fail full schema validation (e.g. legacy/migrated ones) can still be
    approved by their owner.
    """
    request, resource, package = _get_manageable_request(request_id, acting_user)
    if _request_status(request) != STATUS_PENDING:
        raise tk.ValidationError({'request': [_('Request already handled')]})

    if request.user_id:
        allowed = [u.strip() for u in (resource.extras.get('allowed_users') or '').split(',') if u.strip()]
        if request.user_id not in allowed:
            allowed.append(request.user_id)
        resource.extras = dict(resource.extras, allowed_users=','.join(allowed))
    else:
        # unregistered requester: personal download link, sent by email
        request.download_id = base64.b32encode(os.urandom(30)).decode()
    request.accepted_at = datetime.datetime.utcnow()
    model.Session.commit()

    try:
        search.rebuild(package.id)
    except Exception:
        log.exception('Failed to reindex dataset %s after accepting a request', package.name)

    if request.user_id:
        restricted_mail_allowed_user(request.user_id, resource.as_dict())
    else:
        _mail_download_link(request, resource.as_dict())


def _mail_download_link(request, resource_dict):
    try:
        body = restricted_allowed_user_mail_body(resource_dict, download_id=request.download_id)
        subject = _('Αποδοχή αιτήματος πρόσβασης στον πόρο {}').format(resource_dict.get('name', resource_dict['id']))
        send_mail('user', request.request_email, subject, body)
    except Exception as e:
        log.warning('Failed to send download link to "%s": %s', request.request_email, e)


def reject_request(request_id, acting_user):
    request, resource, package = _get_manageable_request(request_id, acting_user)
    if _request_status(request) != STATUS_PENDING:
        raise tk.ValidationError({'request': [_('Request already handled')]})

    request.rejected_at = datetime.datetime.utcnow()
    model.Session.commit()
    _mail_rejection(request, resource, package)


def revoke_request(request_id, acting_user):
    """Withdraw an accepted request.

    Registered requesters are removed from the resource's allowed users;
    unregistered ones lose their download link (it only works while the
    request is accepted and not rejected). The requester is notified.
    """
    request, resource, package = _get_manageable_request(request_id, acting_user)
    if _request_status(request) != STATUS_ACCEPTED:
        raise tk.ValidationError({'request': [_('Request already handled')]})

    if request.user_id:
        allowed = [u.strip() for u in (resource.extras.get('allowed_users') or '').split(',') if u.strip()]
        allowed = [u for u in allowed if u != request.user_id]
        resource.extras = dict(resource.extras, allowed_users=','.join(allowed))
    request.rejected_at = datetime.datetime.utcnow()
    model.Session.commit()

    if request.user_id:
        try:
            search.rebuild(package.id)
        except Exception:
            log.exception('Failed to reindex dataset %s after revoking a request', package.name)
    _mail_rejection(request, resource, package)


def _mail_rejection(request, resource, package):
    requester = model.User.get(request.user_id or '')
    requester_name = requester.display_name if requester else 'user'
    requester_email = requester.email if requester else request.request_email
    if requester_email:
        resource_name = resource.name or resource.id
        body = tk.render('restricted/emails/restricted_user_rejected.txt', {
            'site_title': email_site_title(),
            'site_url': config.get('ckan.site_url'),
            'resource_name': resource_name,
            'package_name': package.title or package.name,
            'admin_email_to': config.get('email_to', 'email_to_undefined')})
        subject = _('Απόρριψη αιτήματος πρόσβασης στον πόρο {}').format(resource_name)
        try:
            send_mail(requester_name, requester_email, subject, body)
        except mailer.MailerException as e:
            log.warning('Failed to send rejection mail to "%s": %s', request.user_id, e)
