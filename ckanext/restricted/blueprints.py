# coding: utf-8
from __future__ import annotations

import re
from logging import getLogger
import simplejson as json

from flask import Blueprint, redirect, request, send_file

from ckan.common import _, g, config
import ckan.model as model
import ckan.logic as logic
import ckan.plugins.toolkit as tk
import ckan.lib.captcha as captcha
import ckan.lib.helpers as h
import ckan.lib.mailer as mailer
import ckan.lib.uploader as uploader
import ckanext.restricted.model as ext_model
import ckanext.restricted.logic as restricted_logic
import ckan.lib.navl.dictization_functions as dictization_functions

log = getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten


# ✅ CKAN 2.10: define a module-level Blueprint object
restricted = Blueprint("restricted", __name__)


@restricted.route(
    "/dataset/<package_id>/restricted_request_access/<resource_id>",
    methods=["GET", "POST"],
)
def restricted_request_access_form(package_id, resource_id):
    """
    Show + handle the restricted access request form.
    """
    # logged in or not: unregistered users identify themselves with an email
    user_obj = model.User.get(g.user) if g.user else None
    context = {
        "model": model,
        "session": model.Session,
        "user": g.user,
        "auth_user_obj": user_obj,
        "save": "save" in request.form,
    }

    # Defaults for rendering
    data = {}
    errors = {}
    error_summary = {}

    # POST submit
    if context["save"]:
        return _send_request(context, package_id, resource_id)

    # GET: build initial form data
    data["package_id"] = package_id
    data["resource_id"] = resource_id

    try:
        if g.user:
            user = tk.get_action("user_show")(context, {"id": g.user})
            data["user_id"] = g.user
            data["user_name"] = user.get("display_name", g.user)
            data["user_email"] = user.get("email", "")

        pkg = tk.get_action("package_show")(context, {"id": package_id})
        data["package_name"] = pkg.get("name")

        resource_name = ""
        for r in pkg.get("resources", []):
            if r.get("id") == resource_id:
                resource_name = r.get("name") or r.get("id")
                break
        else:
            raise tk.ObjectNotFound(_("Dataset resource not found"))

        data["package_title"] = pkg.get("title") or pkg.get("name")
        data["resource_name"] = resource_name

    except tk.ObjectNotFound:
        tk.abort(404, _("Dataset not found"))
    except Exception as e:
        log.exception("Exception retrieving dataset for restricted request form")
        tk.abort(500, _("Exception retrieving dataset for the form ({})").format(str(e)))

    extra_vars = {
        "pkg_dict": pkg,
        "data": data,
        "errors": errors,
        "error_summary": error_summary,
    }
    # ✅ CKAN 2.10: use tk.render
    return tk.render("restricted/restricted_request_access_form.html", extra_vars)


def _send_request(context, package_id, resource_id):
    """
    Handle POST submission: store the request and notify the dataset owner.
    """
    try:
        data_dict = logic.clean_dict(
            unflatten(logic.tuplize_dict(logic.parse_params(request.form)))
        )

        captcha.check_recaptcha(request)

    except logic.NotAuthorized:
        tk.abort(401, _("Not authorized to see this page"))
    except captcha.CaptchaError:
        h.flash_error(_("Bad Captcha. Please try again."))
        # Re-render form with posted data
        extra_vars = {
            "pkg_dict": {},
            "data": data_dict,
            "errors": {},
            "error_summary": {},
        }
        return tk.render("restricted/restricted_request_access_form.html", extra_vars)

    # Load dataset for rendering + email content
    try:
        pkg = tk.get_action("package_show")(context, {"id": package_id})
    except tk.ObjectNotFound:
        tk.abort(404, _("Dataset not found"))

    resource = next((r for r in pkg.get("resources", []) if r.get("id") == resource_id), None)
    if resource is None:
        tk.abort(404, _("Dataset resource not found"))

    # Requester identity and target come from the session / URL, never the form
    if g.user:
        user = tk.get_action("user_show")(context, {"id": g.user})
        user_name = user.get("display_name", g.user)
        user_email = user.get("email", "")
    else:
        user_name = user_email = (data_dict.get("user_email") or "").strip()
    data_dict.update({
        "package_id": pkg["id"],
        "package_name": pkg["name"],
        "package_title": pkg.get("title") or pkg["name"],
        "resource_id": resource_id,
        "resource_name": resource.get("name") or resource_id,
        "user_id": g.user or "",
        "user_name": user_name,
        "user_email": user_email,
    })

    # Basic validation
    errors = {}
    error_summary = {}

    if not (data_dict.get("message") or "").strip():
        msg = _("Missing value")
        errors["message"] = [msg]
        error_summary["message"] = msg

    if not g.user and not EMAIL_RE.match(data_dict["user_email"]):
        msg = _("Please provide a valid email address")
        errors["user_email"] = [msg]
        error_summary["user_email"] = msg

    if errors:
        extra_vars = {
            "pkg_dict": pkg,
            "data": data_dict,
            "errors": errors,
            "error_summary": error_summary,
        }
        return tk.render("restricted/restricted_request_access_form.html", extra_vars)

    if restricted_logic.get_pending_request(g.user, resource_id, data_dict["user_email"]):
        h.flash_notice(_("You have already requested access to this resource."))
        return h.redirect_to("dataset.read", id=pkg["name"])

    owner = restricted_logic.get_package_owner(pkg)
    restricted_logic.save_restricted_request({
        "resource_id": resource_id,
        "owner_id": owner.id if owner else (pkg.get("creator_user_id") or ""),
        "message": data_dict["message"],
        "user_id": g.user or None,
        "request_email": data_dict["user_email"],
    })

    success = _send_request_mail(data_dict, owner)

    return tk.render(
        "restricted/restricted_request_access_result.html",
        {"data": data_dict, "pkg_dict": pkg, "success": success},
    )


def _send_request_mail(data, owner):
    """
    Email the dataset owner (site admin when the owner has not registered yet)
    and send a copy to the requester.
    """
    try:
        site_url = config.get("ckan.site_url")
        # resources are edited from the dataset page (EDIT button opens the modal)
        resource_edit_link = tk.url_for("dataset.read", id=data.get("package_name"))
        admin_email = restricted_logic.admin_email()

        # usernames on this instance are email addresses, use them if the profile email is empty
        owner_email = owner and (owner.email or ("@" in owner.name and owner.name) or None)
        if owner_email:
            recipient_name, recipient_email = owner.display_name, owner_email
        else:
            recipient_name, recipient_email = "{} Admin".format(restricted_logic.email_site_title()), admin_email

        extra_vars = {
            "site_title": restricted_logic.email_site_title(),
            "site_url": site_url,
            "maintainer_name": recipient_name,
            "user_id": data.get("user_id", ""),
            "user_name": data.get("user_name", ""),
            "user_email": data.get("user_email", ""),
            "resource_name": data.get("resource_name", ""),
            "resource_link": site_url + tk.url_for(
                "dataset_resource.read", id=data.get("package_name"), resource_id=data.get("resource_id")),
            "resource_edit_link": site_url + resource_edit_link,
            "dashboard_restricted": site_url + tk.url_for("restricted.dashboard_requests"),
            "package_name": data.get("package_title", ""),
            "message": data.get("message", ""),
            "admin_email_to": admin_email or "email_to_undefined",
        }

        template = (
            "restricted/emails/restricted_access_request.txt" if data.get("user_id")
            else "restricted/emails/restricted_access_unauth_request.txt"
        )
        body = tk.render(template, extra_vars)

        subject = _("Access Request to resource {0} ({1}) from {2}").format(
            data.get("resource_name", ""),
            data.get("package_title", ""),
            data.get("user_name", ""),
        )

        headers = {"reply-to": data.get("user_email")}

        if recipient_email:
            restricted_logic.send_mail(
                recipient_name=recipient_name,
                recipient_email=recipient_email,
                subject=subject,
                body=body,
                body_html=None,
                headers=headers,
            )
        else:
            log.error("No recipient for restricted access request on resource %s", data.get("resource_id"))
            return False

        # Copy to user (no links)
        email = data.get("user_email")
        if email:
            extra_vars_user = dict(extra_vars)
            extra_vars_user["resource_link"] = "[...]"
            extra_vars_user["resource_edit_link"] = "[...]"
            extra_vars_user["dashboard_restricted"] = "[...]"
            body_user_src = tk.render(template, extra_vars_user)
            body_user = _("Please find below a copy of the access request mail sent.\n\n >> {}").format(
                body_user_src.replace("\n", "\n >> ")
            )

            restricted_logic.send_mail(
                recipient_name=data.get("user_name", "User"),
                recipient_email=email,
                subject=subject,
                body=body_user,
                body_html=None,
                headers=headers,
            )

        return True

    except mailer.MailerException as e:
        log.error("MailerException sending restricted request email: %r", e)
        return False
    except Exception:
        log.exception("Unexpected error sending restricted request email")
        return False


@restricted.route("/dashboard/restricted")
def dashboard_requests():
    """Dashboard tab: requests received for my datasets and requests I made."""
    if not g.user:
        h.flash_error(_("Not authorized to see this page"))
        return h.redirect_to("home.index")

    context = {
        "model": model, "session": model.Session, "for_view": True,
        "user": g.user, "auth_user_obj": g.userobj,
        "include_num_followers": False, "include_datasets": False,
    }
    user_dict = tk.get_action("user_show")(context, {"user_obj": g.userobj})

    return tk.render("user/dashboard_restricted.html", {
        "user_dict": user_dict,
        "received_requests": restricted_logic.get_requests_for_owner(g.userobj),
        "my_requests": restricted_logic.get_requests_made_by(g.userobj),
    })


@restricted.route("/dashboard/restricted/<request_id>/<decision>", methods=["POST"])
def dashboard_handle_request(request_id, decision):
    if not g.user:
        tk.abort(401, _("Not authorized to see this page"))
    if decision not in ("accept", "reject", "revoke"):
        tk.abort(404)

    try:
        if decision == "accept":
            restricted_logic.accept_request(request_id, g.userobj)
            h.flash_success(_("Το αίτημα έγινε δεκτό"))
        elif decision == "reject":
            restricted_logic.reject_request(request_id, g.userobj)
            h.flash_success(_("Το αίτημα απορρίφθηκε"))
        else:
            restricted_logic.revoke_request(request_id, g.userobj)
            h.flash_success(_("Η πρόσβαση ανακλήθηκε"))
    except tk.ObjectNotFound:
        tk.abort(404, _("Request not found"))
    except tk.ValidationError:
        h.flash_error(_("Request already handled"))

    return h.redirect_to("restricted.dashboard_requests")


@restricted.route("/restricted/download/<download_id>")
def download_resource(download_id):
    """Personal download link sent to unregistered requesters once accepted."""
    req = model.Session.query(ext_model.RestrictedRequest).filter_by(
        download_id=download_id, rejected_at=None).one_or_none()
    if req is None or req.accepted_at is None:
        tk.abort(404, _("Not found"))

    context = {"model": model, "session": model.Session, "ignore_auth": True}
    try:
        resource = tk.get_action("resource_show")(context, {"id": req.resource_id})
    except tk.ObjectNotFound:
        tk.abort(404, _("Not found"))

    return _send_resource(resource)


@restricted.route("/restricted/resource/<resource_id>/download")
def download_resource_as_user(resource_id):
    """Download link for registered users: forces a download instead of opening the file in the browser."""
    if not g.user:
        return h.redirect_to("user.login", came_from=request.full_path.rstrip("?"))

    context = {"model": model, "session": model.Session, "user": g.user, "auth_user_obj": g.userobj}
    try:
        resource = tk.get_action("resource_show")(dict(context, ignore_auth=True), {"id": resource_id})
        tk.check_access("resource_show", context, {"id": resource_id, "resource": resource})
    except tk.ObjectNotFound:
        tk.abort(404, _("Not found"))
    except tk.NotAuthorized:
        tk.abort(403, _("Not authorized to download this resource"))
    return _send_resource(resource)


def _send_resource(resource):
    # linked (not uploaded) resources are just redirected to their URL
    if resource.get("url_type") != "upload":
        return redirect(resource["url"])

    path = uploader.get_resource_uploader(resource).get_path(resource["id"])
    filename = (resource.get("url") or "").rsplit("/", 1)[-1] or resource.get("name") or resource["id"]
    log.info("Downloading restricted resource %s", resource["id"])
    return send_file(path, as_attachment=True, download_name=filename,
                     mimetype=resource.get("mimetype") or None)
