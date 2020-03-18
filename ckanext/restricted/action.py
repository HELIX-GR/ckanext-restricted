# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _, c

from ckan.lib.base import render_jinja2, render
from ckan.lib.mailer import mail_recipient
from ckan.lib.mailer import MailerException
import ckan.plugins.toolkit as toolkit

import ckan.lib.mailer as mailer
import ckan.logic
from ckan.logic.action.create import user_create
from ckan.logic.action.get import package_search
from ckan.logic.action.get import package_show
from ckan.logic.action.get import resource_search
from ckan.logic.action.get import resource_view_list
from ckan.logic import side_effect_free
from ckan.logic import get_action
from ckanext.restricted import auth
from ckanext.restricted import logic
import json
import os
import base64
import datetime
from ckan.lib.base import render

import ckan.model as model
import ckan.lib.helpers as h

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger
log = getLogger(__name__)


_get_or_bust = ckan.logic.get_or_bust

NotFound = ckan.logic.NotFound


def restricted_user_create_and_notify(context, data_dict):

    def body_from_user_dict(user_dict):
        body = ''
        for key, value in user_dict.items():
            body += '* {0}: {1}\n'.format(
                key.upper(), value if isinstance(value, str) else str(value))
        return body

    user_dict = user_create(context, data_dict)

    # Send your email, check ckan.lib.mailer for params
    try:
        name = _('CKAN System Administrator')
        email = config.get('email_to')
        if not email:
            raise MailerException('Missing "email-to" in config')

        subject = _('New Registration: {0} ({1})').format(
            user_dict.get('name', _(u'new user')), user_dict.get('email'))

        extra_vars = {
            'site_title': config.get('ckan.site_title'),
            'site_url': config.get('ckan.site_url'),
            'user_info': body_from_user_dict(user_dict)}

        body = render_jinja2(
            'restricted/emails/restricted_user_registered.txt', extra_vars)

        mail_recipient(name, email, subject, body)

    except MailerException as mailer_exception:
        log.error('Cannot send mail after registration')
        log.error(mailer_exception)

    return (user_dict)


@side_effect_free
def restricted_resource_view_list(context, data_dict):
    model = context['model']
    id = _get_or_bust(data_dict, 'id')
    resource = model.Resource.get(id)
    if not resource:
        raise NotFound
    authorized = auth.restricted_resource_show(
        context, {'id': resource.get('id'), 'resource': resource}).get('success', False)
    if not authorized:
        return []
    else:
        return resource_view_list(context, data_dict)


@side_effect_free
def restricted_package_show(context, data_dict):
    package_metadata = package_show(context, data_dict)

    # Ensure user who can edit can see the resource
    if authz.is_authorized(
            'package_update', context, package_metadata).get('success', False):
        return package_metadata

    # Custom authorization
    if isinstance(package_metadata, dict):
        restricted_package_metadata = dict(package_metadata)
    else:
        restricted_package_metadata = dict(package_metadata.for_json())

    # restricted_package_metadata['resources'] = _restricted_resource_list_url(
    #     context, restricted_package_metadata.get('resources', []))
    restricted_package_metadata['resources'] = _restricted_resource_list_hide_fields(
        context, restricted_package_metadata.get('resources', []))

    return (restricted_package_metadata)


@side_effect_free
def restricted_resource_search(context, data_dict):
    resource_search_result = resource_search(context, data_dict)

    restricted_resource_search_result = {}

    for key, value in resource_search_result.items():
        if key == 'results':
            # restricted_resource_search_result[key] = \
            #     _restricted_resource_list_url(context, value)
            restricted_resource_search_result[key] = \
                _restricted_resource_list_hide_fields(context, value)
        else:
            restricted_resource_search_result[key] = value

    return restricted_resource_search_result


@side_effect_free
def restricted_package_search(context, data_dict):
    package_search_result = package_search(context, data_dict)

    restricted_package_search_result = {}

    for key, value in package_search_result.items():
        if key == 'results':
            restricted_package_search_result_list = []
            for package in value:
                restricted_package_search_result_list.append(
                    restricted_package_show(context, {'id': package.get('id')}))
            restricted_package_search_result[key] = \
                restricted_package_search_result_list
        else:
            restricted_package_search_result[key] = value

    return restricted_package_search_result


@side_effect_free
def restricted_check_access(context, data_dict):

    package_id = data_dict.get('package_id', False)
    resource_id = data_dict.get('resource_id', False)

    user_name = logic.restricted_get_username_from_context(context)

    if not package_id:
        raise ckan.logic.ValidationError('Missing package_id')
    if not resource_id:
        raise ckan.logic.ValidationError('Missing resource_id')

    log.debug("action.restricted_check_access: user_name = " + str(user_name))

    log.debug("checking package " + str(package_id))
    package_dict = ckan.logic.get_action('package_show')(
        dict(context, return_type='dict'), {'id': package_id})
    log.debug("checking resource")
    resource_dict = ckan.logic.get_action('resource_show')(
        dict(context, return_type='dict'), {'id': resource_id})

    return logic.restricted_check_user_resource_access(user_name, resource_dict, package_dict)

# def _restricted_resource_list_url(context, resource_list):
#     restricted_resources_list = []
#     for resource in resource_list:
#         authorized = auth.restricted_resource_show(
#             context, {'id': resource.get('id'), 'resource': resource}).get('success', False)
#         restricted_resource = dict(resource)
#         if not authorized:
#             restricted_resource['url'] = _('Not Authorized')
#         restricted_resources_list += [restricted_resource]
#     return restricted_resources_list


def _restricted_resource_list_hide_fields(context, resource_list):
    restricted_resources_list = []
    for resource in resource_list:
        # copy original resource
        restricted_resource = dict(resource)

        # get the restricted fields
        restricted_dict = logic.restricted_get_restricted_dict(
            restricted_resource)

        # hide fields to unauthorized users
        authorized = auth.restricted_resource_show(
            context, {'id': resource.get('id'), 'resource': resource}
        ).get('success', False)

        # hide other fields in restricted to everyone but dataset owner(s)
        if not authz.is_authorized(
                'package_update', context, {'id': resource.get('package_id')}
        ).get('success'):

            user_name = logic.restricted_get_username_from_context(context)

            # hide partially other allowed user_names (keep own)
            allowed_users = []
            # convert to list if only 1 string
            list_allowed_users = restricted_dict.get('allowed_users')
            for user in list_allowed_users:
                if len(user.strip()) > 0:
                    if user_name == user:
                        allowed_users.append(user_name)
                    else:
                        allowed_users.append(user[0:3] + '*****' + user[-2:])
            # hide usernames from custom allowed users field
            restricted_resource['allowed_users'] = allowed_users

            new_restricted = json.dumps({
                'level': restricted_dict.get("level"),
                'allowed_users': ','.join(allowed_users)})
            extras_restricted = resource.get(
                'extras', {}).get('restricted', {})
            if (extras_restricted):
                restricted_resource['extras']['restricted'] = new_restricted

            field_restricted_field = resource.get('restricted', {})
            if (field_restricted_field):
                restricted_resource['restricted'] = new_restricted

        restricted_resources_list += [restricted_resource]
    return restricted_resources_list


def restricted_accept_request(context, data_dict):
    request_id = data_dict.get('request_id')
    resource_id = data_dict.get('resource_id')
    user_id = data_dict.get('user_id')
    request_email = data_dict.get('request_email')
    resource = ckan.logic.get_action(
        'resource_show')(context, {'id': resource_id})
    # registered and external requests
    if user_id:
        allowed_users = resource.get('allowed_users')
        if allowed_users:
            resource['allowed_users'] = resource['allowed_users'] + \
                ',' + user_id
        else:
            resource['allowed_users'] = user_id
        ckan.logic.get_action('resource_update')(context, resource)
        download_id = resource.get('url')
    else:
        # send email
        download_id = base64.b32encode(os.urandom(30))
        #log.debug('restricted_mail_allowed_user: Notifying "{}"'.format(user_id))
        try:
            # Get user information
            context = {}
            context['ignore_auth'] = True
            context['keep_email'] = True
            resource_name = resource.get('name', resource['id'])
            mail_body = logic.restricted_allowed_user_mail_body(
                resource=resource, download_id=download_id)
            mail_subject = _('Αποδοχή αιτήματος πρόσβασης στον πόρο {}').format(
                resource_name)

            # Send mail to user
            mailer.mail_recipient("user", request_email,
                                  mail_subject, mail_body)

        except Exception as e:
            log.warning(('restricted_mail_allowed_user: '
                         'Failed to send mail to "{0}": {1}').format(user_id, e))
        log.debug('Mail Sent')
    now = datetime.datetime.now()
    request_dict = {'request_id': request_id,
                    'download_id': download_id,
                    'accepted_at': now}
    logic.update_restricted_request(request_dict)

    h.flash_success(_('Το αίτημα έγινε δεκτό'))
    h.redirect_to(controller='user', action='restricted')


def restricted_reject_request(context, data_dict):
    request_id = data_dict.get('request_id')
    resource_id = data_dict.get('resource_id')
    user_id = data_dict.get('user_id')
    # for authorized users
    if user_id:
        resource = ckan.logic.get_action(
            'resource_show')(context, {'id': resource_id})
        allowed_users = resource.get('allowed_users', '')
        if user_id in allowed_users:
            list_allowed_users = allowed_users.split(',')
            list_allowed_users.remove(user_id)
            resource['allowed_users'] = ','.join(list_allowed_users)
        ckan.logic.get_action('resource_update')(context, resource)
    now = datetime.datetime.now()
    request_dict = {'request_id': request_id,
                    'rejected_at': now}
    logic.update_restricted_request(request_dict)
    h.flash_success(_('Το αίτημα απορρίφθηκε'))
    #h.redirect_to(controller='user', action='restricted')


def request_resource(context, data_dict):
    '''Sent Email with a resource request to the owner of a dataset.'''
    contact_email = data_dict.get('contact_email')
    owner_id = data_dict.get('creator_id')
    resource_id = data_dict.get('resource_id')
    resource_link = toolkit.url_for(
        action='resource_read',
        controller='package',
        id=data_dict.get('package_name'),
        resource_id=resource_id)
    dashboard_restricted = config.get(
        'ckan.site_url') + '/dashboard/restricted'
    # create request e-mail
    extra_vars = {
        'site_title': config.get('ckan.site_title'),
        'site_url': config.get('ckan.site_url'),
        'user_email': data_dict.get('email'),
        'resource_name': data_dict.get('resource_name'),
        'resource_link': config.get('ckan.site_url') + resource_link,
        'package_name': data_dict.get('pkg_title'),
        'message': data_dict.get('message', ''),
        'dashboard_restricted': dashboard_restricted,
        'admin_email_to': config.get('email_to', 'email_to_undefined')}

    body = render_jinja2(
        'restricted/emails/restricted_access_unauth_request.txt', extra_vars)
    subject = \
        _('Αίτημα πρόσβασης στο {0}  από τον χρήστη {1}').format(
            data_dict.get('resource_name'),
            data_dict.get('email'))

    # send e-mail
    try:
        ckan.lib.mailer.mail_recipient(data_dict.get('email'), contact_email,
                                       subject, body)
    except ckan.lib.mailer.MailerException:
        success = False
        # return 'Error sending e-mail'

    request_dict = {'resource_id': resource_id, 'message': data_dict.get('message'),
                    'owner_id': owner_id, 'request_email': data_dict.get('email')
                    }

    logic.save_restricted_request(request_dict)

    # return _('Mail sent!')
    data = {'resource_id': resource_id, 'maintainer_email': contact_email,
            'user_email': data_dict.get('email'), 'package_title':data_dict.get('pkg_title'),
            'message': data_dict.get('message')}
    return render(
        'restricted/restricted_request_access_result.html',
        extra_vars={'data': data, 'success': True})
