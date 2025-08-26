from app import root
from flask import render_template

@root.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@root.errorhandler(401)
def unauthorized(e):
    return render_template('errors/401.html'), 401

@root.errorhandler(403)
def permission_denied(e):
    return render_template('errors/403.html'), 403