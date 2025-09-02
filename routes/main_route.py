from app import root
from models import db
from models.todo import Todo
from models.user import User
from models.role import Role
from models.permission import Permission
from models.role_permission import RolePermission
from models.user_permission import UserPermission
from flask import render_template, request, redirect, url_for
from flask_login import login_required, current_user

@root.route('/')
@root.route('/home')
@login_required
def home_page():
    return redirect(url_for('login_page'))

def get_permissions_and_role(user_id):
    user = User.query.filter_by(id=user_id).first()
    role_permissions = [Permission.query.filter_by(id = rp.permission_id).first() for rp in RolePermission.query.filter_by(role_id=user.role_id, is_deleted=False).all()]
    user_permissions = [Permission.query.filter_by(id = up.permission_id).first() for up in UserPermission.query.filter_by(user_id = user.id, is_deleted = False).all()]
    all_permissions_dict = {p.id: p.permission for p in role_permissions + user_permissions if p}
    distinct_permissions = list(all_permissions_dict.values())
    return [distinct_permissions, Role.query.filter_by(id = user.role_id).first().role]


@root.context_processor
def global_variables():
    if request.endpoint and current_user.is_authenticated and (request.endpoint.startswith('admin') or request.endpoint.startswith('my')):
        user = User.query.filter_by(is_deleted = False, id = current_user.id).first()
        return {'full_name':current_user.full_name, 'role':Role.query.filter_by(is_deleted = False, id = user.role_id).first().role}
    return {}