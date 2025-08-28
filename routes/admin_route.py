from app import root
from models import db
from sqlalchemy import or_
from models.todo import Todo
from models.user import User
from models.role import Role
from models.project import Project
from models.permission import Permission
from models.project_column import ProjectColumn
from models.user_permission import UserPermission
from models.role_permission import RolePermission
from flask_login import login_required, current_user
from routes.main_route import get_permissions_and_role
from flask import render_template, request, flash, redirect, url_for, abort
from forms.admin_forms import UserCreateForm, ProjectCreateForm, TodoCreateForm, ProjectColumnCreateForm

@root.route('/admin')
@login_required
def admin_page():
    info = get_permissions_and_role(current_user.id)
    columns = (
    ProjectColumn.query
        .filter_by(is_deleted=False)
        .order_by(ProjectColumn.order)
        .all()
    )
    project_columns = []
    for c in columns:
        project_columns.append({'column':c, 'projects':Project.query.filter_by(column_id = c.id, is_deleted = False).all()})
    return render_template('admin/home.html', project_columns=project_columns)
    
@root.route("/change_column/<int:project_id>", methods=["POST"])
@login_required
def change_column(project_id: int):
    info = get_permissions_and_role(current_user.id)
    if 'edit_project_column' not in info[0]:
        abort(403)
    project = Project.query.filter_by(id = project_id).first()
    max_column = ProjectColumn.query.filter_by(is_deleted = False).order_by(ProjectColumn.order.desc()).first()
    current_order = ProjectColumn.query.filter_by(id = project.column_id).first().order
    if request.form.get('left'):
        if current_order > 1:
            new_column = ProjectColumn.query.filter_by(order = current_order - 1, is_deleted = False).first()
            if new_column:
                project.column_id = new_column.id
                db.session.commit()
        else:
            project.column_id = max_column.id
            db.session.commit()
    elif request.form.get('right'):
        if current_order < max_column.order:
            new_column = ProjectColumn.query.filter_by(order = current_order + 1, is_deleted = False).first()
            if new_column:
                project.column_id = new_column.id
                db.session.commit()
        else:
            project.column_id = max_column.id
            db.session.commit()
    return redirect(url_for('admin_page'))

@root.route('/project-detail/<int:project_id>')
def admin_project_detailed_page(project_id: int):
    info = get_permissions_and_role(current_user.id)
    if request.method == 'GET' and 'view_projects' in info[0]:
        project = Project.query.filter_by(id = project_id).first()
        project_todos = Todo.query.filter_by(project_id = project_id, is_deleted = False).all()
        return render_template('admin/project_detail.html', project = project, todos = project_todos)
    else:
        abort(403)

@root.route('/admin-users', methods = ['GET', 'POST'])
@login_required
def admin_users_page():
    info = get_permissions_and_role(current_user.id)
    users = User.query.filter_by(is_deleted = False).all()
    user_team_leads = []
    id = Role.query.filter_by(role = 'team-lead').first()
    if id is not None:
        id = id.id
    all_team_leads = User.query.filter_by(is_deleted = False, role_id = id).all()
    roles = Role.query.filter_by(is_deleted = False).all()
    form = UserCreateForm(all_team_leads, roles)
    roles = []
    for user in users:
        full_name = "Nobody"
        u = User.query.filter_by(id = user.team_lead_id).first()
        r = Role.query.filter_by(id = user.role_id).first()
        if u != None:
            full_name = u.full_name
        roles.append(r)
        user_team_leads.append(full_name)
    if request.method == 'GET' and 'view_users' in info[0]:
        return render_template('admin/users.html', users = users, team_leads = user_team_leads, form = form, roles = roles)
    elif request.form.get('search'):
        text = request.form.get('search_text')
        result = User.query.filter(
            or_(
                User.username.ilike(f"%{text}%"),
                User.full_name.ilike(f"%{text}%"),
                User.email.ilike(f"%{text}%")
            )
        ).all()
        return render_template('admin/users.html', users = result, team_leads = user_team_leads, form = form, roles = roles)
    elif request.form.get('update_user') and 'edit_users' in info[0]:
        user_id = request.form.get('update_user')
        user = User.query.filter_by(id = user_id).first()
        team_lead_id = form.team_lead.data
        if team_lead_id == "None":
            team_lead_id = None
        user.team_lead_id = team_lead_id
        role_id = Role.query.filter_by(role = form.role.data).first()
        user.role_id = role_id.id if role_id else None
        db.session.commit()
        flash("User successfully updated", "success")
        return redirect(url_for('admin_users_page'))
    elif form.validate_on_submit() and 'create_users' in info[0]:
        if User.query.filter_by(email = form.email.data).first() is None and User.query.filter_by(username = form.username.data).first() is None:
            team_lead_id = form.team_lead.data
            if team_lead_id == "None":
                team_lead_id = None
            role_id = Role.query.filter_by(role = form.role.data, is_deleted = False).first()
            if role_id is not None:
                role_id = role_id.id
            user = User(team_lead_id, form.full_name.data, form.username.data, form.password.data, form.email.data, role_id)
            db.session.add(user)
            db.session.commit()
            flash("User successfully created", "success")
        else:
            flash("Both email and username should be unique", 'danger')
        return redirect(url_for('admin_users_page'))
    elif request.form.get('delete_user') and 'delete_users' in info[0]:
        user_id = request.form.get('delete_user')
        user = User.query.filter_by(id = user_id).first()
        user.is_deleted = True
        db.session.commit()
        flash("User successfully deleted", "success")
        return redirect(url_for('admin_users_page'))
    else:
        abort(403)
    

@root.route('/admin-roles', methods = ['GET','POST'])
@login_required
def admin_roles_page():
    info = get_permissions_and_role(current_user.id)
    roles = Role.query.filter_by(is_deleted = False).all()
    if request.method == 'GET' and 'view_roles' in info[0]:
        return render_template('admin/roles.html', roles = roles)
    elif request.form.get('update_role') and 'edit_roles' in info[0]:
        role_id = request.form.get('update_role')
        role = Role.query.filter_by(id = role_id).first()
        role.role = request.form.get('role_name')
        db.session.commit()
        flash("Role successfully updated", "success")
        return redirect(url_for('admin_roles_page'))
    elif request.form.get('delete_role') and 'delete_roles' in info[0]:
        role_id = request.form.get('delete_role')
        role = Role.query.filter_by(id = role_id).first()
        role.is_deleted = True
        db.session.commit()
        flash("Role successfully deleted", "success")
        return redirect(url_for('admin_roles_page'))
    elif request.form.get('create_role') and 'create_roles' in info[0]:
        role = request.form.get('role')
        new_role = Role(role = role)
        db.session.add(new_role)
        db.session.commit()
        flash("Role successfully created", "success")
        return redirect(url_for('admin_roles_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        result = Role.query.filter(Role.role.ilike(f"%{text}%")).all()
        return render_template('admin/roles.html', roles = result)
    else:
        abort(403)
    
@root.route('/admin-permissions', methods = ['GET', 'POST'])
@login_required
def admin_permissions_page():
    info = get_permissions_and_role(current_user.id)
    permissions = Permission.query.filter_by(is_deleted = False).all()
    if request.method == 'GET' and 'view_permissions' in info[0]:
        return render_template('admin/permissions.html', permissions = permissions)
    elif request.form.get('update_permission') and 'edit_permissions' in info[0]:
        permission_id = request.form.get('update_permission')
        permission = Permission.query.filter_by(id = permission_id).first()
        permission.permission = request.form.get('permission_name')
        db.session.commit()
        flash("Permission successfully updated", "success")
        return redirect(url_for('admin_permissions_page'))
    elif request.form.get('delete_permission') and 'delete_permissions' in info[0]:
        permission_id = request.form.get('delete_permission')
        permission = Permission.query.filter_by(id = permission_id).first()
        permission.is_deleted = True
        db.session.commit()
        flash("Permission successfully deleted", "success")
        return redirect(url_for('admin_permissions_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        result = Permission.query.filter(Permission.permission.ilike(f"%{text}%")).all()
        return render_template('admin/permissions.html', permissions = result)
    elif request.form.get('create_permission') and 'create_permissions' in info[0]:
        permission = request.form.get('permission')
        new_permission = Permission(permission = permission)
        db.session.add(new_permission)
        db.session.commit()
        flash("Permission successfully created", "success")
        return redirect(url_for('admin_permissions_page'))
    else:
        abort(403)
    
@root.route('/admin-permissions/user-permissions', methods = ['GET', 'POST'])
@login_required
def admin_user_permissions_page():
    info = get_permissions_and_role(current_user.id)
    permissions = Permission.query.filter_by(is_deleted = False).all()
    users = User.query.filter_by(is_deleted = False).all()
    user_permission = UserPermission.query.filter_by(is_deleted = False).all()
    if request.method == 'GET' and 'view_user_permission' in info[0]:
        return render_template('admin/user_permission.html', permissions = permissions, users = users, user_permission = user_permission)
    elif request.form.get('save_changes') and 'edit_user_permission' in info[0]:
        for user in users:
            for permission in permissions:
                user_permission = UserPermission.query.filter_by(user_id = user.id, permission_id = permission.id).first()
                if request.form.get(f'user_{user.id}_permission_{permission.id}') is not None:
                    if not user_permission:
                        new_u_p = UserPermission(user.id, permission.id)
                        db.session.add(new_u_p)
                    elif user_permission and user_permission.is_deleted == True:
                        user_permission.is_deleted = False
                elif user_permission:
                    user_permission.is_deleted = True
        db.session.commit()
        return redirect(url_for('admin_user_permissions_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        users = User.query.filter(
            User.full_name.ilike(f"%{text}%"),
            User.is_deleted == False
        ).all()
        return render_template('admin/user_permission.html', permissions = permissions, users = users, user_permission = user_permission)
    else:
        abort(403)

@root.route('/admin-permissions/role-permissions', methods = ['GET', 'POST'])
@login_required
def admin_role_permissions_page():
    info = get_permissions_and_role(current_user.id)
    roles = Role.query.filter_by(is_deleted = False).all()
    permissions = Permission.query.filter_by(is_deleted = False).all()
    role_permission = RolePermission.query.filter_by(is_deleted = False).all()
    if request.method == 'GET' and 'view_role_permission' in info[0]:
        return render_template('admin/role_permission.html', roles = roles, permissions = permissions, role_permission = role_permission)
    elif request.form.get('save_changes') and 'edit_role_permission' in info[0]:
        for role in roles:
            for permission in permissions:
                role_permission = RolePermission.query.filter_by(role_id = role.id, permission_id = permission.id).first()
                if request.form.get(f'role_{role.id}_permission_{permission.id}') is not None:
                    if not role_permission:
                        new_r_p = RolePermission(role.id, permission.id)
                        db.session.add(new_r_p)
                    elif role_permission and role_permission.is_deleted == True:
                        role_permission.is_deleted = False
                elif role_permission:
                    role_permission.is_deleted = True
        db.session.commit()
        return redirect(url_for('admin_role_permissions_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        roles = Role.query.filter(
            Role.role.ilike(f"%{text}%"),
            Role.is_deleted == False
        ).all()
        return render_template('admin/role_permission.html', roles = roles, permissions = permissions, role_permission = role_permission)
    else:
        abort(403)

@root.route('/admin-projects', methods = ['GET', 'POST'])
@login_required
def admin_projects_page():
    info = get_permissions_and_role(current_user.id)
    projects = Project.query.filter_by(is_deleted = False).all()
    column_choices = ProjectColumn.query.filter_by(is_deleted = False).all()
    team_leads = []
    for p in projects:
        if p.team_lead_id is not None:
            team_lead = User.query.filter_by(id = p.team_lead_id, is_deleted = False).first()
            if team_lead:
                team_leads.append(team_lead.full_name)
            else:
                team_leads.append("Nobody")
        else:
            team_leads.append("Nobody")
    role_id = Role.query.filter_by(is_deleted = False, role = 'team-lead').first().id
    form = ProjectCreateForm(User.query.filter_by(role_id = role_id).all(), column_choices)
    if request.method == 'GET' and 'view_projects' in info[0]:
        return render_template('admin/projects.html', projects=projects, team_leads = team_leads, form = form, column_choices = column_choices)
    elif request.form.get('delete_project') and 'delete_projects' in info[0]:
        project_id = request.form.get('delete_project')
        project = Project.query.filter_by(id = project_id).first()
        project.is_deleted = True
        db.session.commit()
        flash("Project successfully deleted", "success")
        return redirect(url_for('admin_projects_page'))
    elif request.form.get('update_project') and 'edit_projects' in info[0]:
        project_id = request.form.get('update_project')
        project = Project.query.filter_by(id = project_id).first()
        team_lead_id = form.team_lead.data
        if team_lead_id == "None":
            team_lead_id = None
        project.team_lead_id = team_lead_id
        project.title = form.title.data
        project.description = form.description.data
        project.deadline = form.deadline.data
        project.column_id = form.status.data
        db.session.commit()
        flash("Project successfully updated", "success")
        return redirect(url_for('admin_projects_page'))
    elif form.validate_on_submit() and 'create_projects' in info[0]:
        team_lead_id = form.team_lead.data
        if team_lead_id == "None":
            team_lead_id = None
        project = Project(team_lead_id, form.title.data, form.description.data, form.deadline.data)
        db.session.add(project)
        db.session.commit()
        flash("Project successfully created", 'success')
        return redirect(url_for('admin_projects_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        result = Project.query.filter(
            or_(
                Project.title.ilike(f"%{text}%"),
                Project.description.ilike(f"%{text}%")
            )
        ).all()
        return render_template('admin/projects.html', projects = result, team_leads = team_leads, form = form, column_choices = column_choices)
    else:
        abort(403)
        
    
@root.route('/admin-todos', methods = ['GET', 'POST'])
@login_required
def admin_todos_page():
    info = get_permissions_and_role(current_user.id)
    todos = Todo.query.filter_by(is_deleted = False).all()
    u_owners = [User.query.filter_by(id = todo.user_id).first() for todo in todos]
    p_owners = [Project.query.filter_by(id = todo.project_id).first() for todo in todos]
    form = TodoCreateForm(
        users = User.query.filter_by(is_deleted = False).all(),
        projects = Project.query.filter_by(is_deleted = False).all()
    )
    if request.method == 'GET' and 'view_todos' in info[0]:
        return render_template('admin/todos.html', todos = todos, u_owners = u_owners, p_owners = p_owners, form = form)
    elif request.form.get('update_todo') and 'edit_todos' in info[0]:
        todo_id = request.form.get('update_todo')
        todo = Todo.query.filter_by(id = todo_id).first()
        user_id = form.user_id.data
        project_id = form.project_id.data
        if user_id == "None":
            user_id = None
        if project_id == 'None':
            project_id = None
        todo.user_id = user_id
        todo.project_id = project_id
        todo.title = form.title.data
        todo.priority = form.priority.data
        todo.description = form.description.data
        todo.deadline = form.deadline.data
        todo.status = form.status.data
        db.session.commit()
        flash("Todo successfully updated", "success")
        return redirect(url_for('admin_todos_page'))
    elif form.validate_on_submit() and 'create_todos' in info[0]:
        user_id = form.user_id.data
        project_id = form.project_id.data
        if user_id == "None":
            user_id = None
        if project_id == 'None':
            project_id = None
        todo = Todo(user_id, project_id, form.title.data, form.description.data, form.deadline.data, form.priority.data)
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for('admin_todos_page'))
    elif request.form.get('delete_todo') and 'delete_todos' in info[0]:
        todo_id = request.form.get('delete_todo')
        todo = Todo.query.filter_by(id = todo_id).first()
        todo.is_deleted = True
        db.session.commit()
        flash("Todo successfully deleted", "success")
        return redirect(url_for('admin_todos_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        result = Todo.query.filter(
            or_(
                Todo.title.ilike(f"%{text}%"),
                Todo.description.ilike(f"%{text}%")
            ), Todo.is_deleted == False
        ).all()
        u_owners = [User.query.filter_by(id = todo.user_id).first() for todo in result]
        p_owners = [Project.query.filter_by(id = todo.project_id).first() for todo in result]
        return render_template('admin/todos.html', todos = result, u_owners = u_owners, p_owners = p_owners, form = form)   
    else:
        abort(403)

@root.route('/admin-project-columns', methods = ['GET', 'POST'])
@login_required
def admin_project_columns_page():
    info = get_permissions_and_role(current_user.id)
    project_columns = (
    ProjectColumn.query
        .filter_by(is_deleted=False)
        .order_by(ProjectColumn.order)
        .all()
    )
    form = ProjectColumnCreateForm()
    if request.method == 'GET' and 'view_project_column' in info[0]:
        return render_template('admin/project_column.html', columns = project_columns, form = form)
    elif request.form.get('update_project_column') and 'edit_project_column' in info[0]:
        pc_id = request.form.get('update_project_column')
        pc = ProjectColumn.query.filter_by(id = pc_id).first()
        pc.column = request.form.get('update_column')
        pc.order = request.form.get('update_order')
        db.session.commit()
        flash("Project column successfully updated", 'success')
        return redirect(url_for('admin_project_columns_page'))
    elif form.validate_on_submit() and 'create_project_column' in info[0]:
        pc = ProjectColumn(form.column.data, form.order.data)
        db.session.add(pc)
        db.session.commit()
        flash("Project column successfully created", "success")
        return redirect(url_for('admin_project_columns_page'))
    elif request.form.get('delete_project_column') and 'delete_project_column' in info[0]:
        project_column_id = request.form.get('delete_project_column')
        pc = ProjectColumn.query.filter_by(id = project_column_id).first()
        pc.is_deleted = True
        db.session.commit()
        flash("Project-Column successfuly deleted", 'success')
        return redirect(url_for('admin_project_columns_page'))
    else:
        print(form.errors)
        abort(403)