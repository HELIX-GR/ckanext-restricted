# coding: utf-8
from __future__ import annotations

from logging import getLogger

import ckan.plugins as plugins
import ckan.plugins.toolkit as tk

from ckanext.restricted import action, auth, helpers, logic
import ckanext.restricted.model as ext_model

log = getLogger(__name__)


class RestrictedPlugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IResourceController, inherit=True)

    # IConfigurable
    def configure(self, config):
        # Setup database table(s)
        ext_model.setup()

    # IConfigurer
    def update_config(self, config_):
        tk.add_template_directory(config_, "templates")
        tk.add_public_directory(config_, "public")
        tk.add_resource("fanstatic", "restricted")

    # IActions
    def get_actions(self):
        return {
            "resource_view_list": action.restricted_resource_view_list,
            "package_show": action.restricted_package_show,
            "resource_search": action.restricted_resource_search,
            "package_search": action.restricted_package_search,
            "restricted_check_access": action.restricted_check_access,
        }

    # ITemplateHelpers
    def get_helpers(self):
        return {
            "restricted_get_user_id": helpers.restricted_get_user_id,
            "get_restricted_requests": helpers.get_restricted_requests,
        }

    # IAuthFunctions
    def get_auth_functions(self):
        return {
            "resource_show": auth.restricted_resource_show,
            "resource_view_show": auth.restricted_resource_show,
        }

    def get_blueprint(self):
        from ckanext.restricted.blueprints import restricted

        return restricted

    # IResourceController
    def before_update(self, context, current, resource):
        context["__restricted_previous_value"] = current.get("allowed_users", [])

    def after_update(self, context, resource):
        previous_value = context.get("__restricted_previous_value")
        logic.restricted_notify_allowed_users(previous_value, resource)
