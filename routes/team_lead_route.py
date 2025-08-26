from app import root
from models import db
from sqlalchemy import or_
from models.user import User
from models.todo import Todo
from models.project import Project
from forms.admin_forms import TodoCreateForm
from flask_login import login_required, current_user
from flask import render_template, request, redirect, url_for, flash, abort

@root.route('/my-user-todos', methods = ['GET','POST'])
@login_required
def my_user_todos_page():
    if request.method == 'GET':
        user_todos = Todo.query.filter_by(user_id = current_user.id, is_deleted = False).all()
        return render_template('admin/todo_users.html', todos = user_todos)
    elif request.form.get('todo_status'):
        status = request.form.get('todo-status').split(',')[0]
        id = int(request.form.get('todo-status').split(',')[1])
        todo = Todo.query.filter_by(id = id).first()
        todo.user_status = status
        db.session.commit()
        flash('Successfully updated todo','success')
        return redirect(url_for('my_user_todos_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        result = Todo.query.filter(
            or_(
                Todo.title.ilike(f"%{text}%"),
                Todo.description.ilike(f"%{text}%")
            ), Todo.is_deleted == False
        ).all()
        return render_template('admin/todo_users.html', todos = result)
    else:
        abort(403)

@root.route('/my-project-todos', methods = ['GET', 'POST'])
@login_required
def my_project_todos_page():
    if request.method == 'GET':
        team_lead_id = User.query.filter_by(id = current_user.id).first().team_lead_id
        projects = Project.query.filter(
            Project.is_deleted == False,
            or_(
                Project.team_lead_id == team_lead_id,
                Project.team_lead_id == current_user.id
            )
        ).all()
        ps = []
        for project in projects:
            data = {"project_title":project.title}
            data.update({"project_todos": Todo.query.filter_by(is_deleted = False, project_id = project.id).all()})
            ps.append(data)
        return render_template('admin/todo_projects.html', projects = ps)
    elif request.form.get('todo-status'):
        status = request.form.get('todo-status').split(',')[0]
        id = int(request.form.get('todo-status').split(',')[1])
        todo = Todo.query.filter_by(id = id).first()
        todo.user_status = status
        db.session.commit()
        flash('Successfully updated todo','success')
        return redirect(url_for('my_project_todos_page'))
    elif request.form.get('search'):
        text = request.form.get('search_text')
        team_lead_id = User.query.filter_by(id = current_user.id).first().team_lead_id
        projects = Project.query.filter(
            Project.is_deleted == False,
            or_(
                Project.team_lead_id == team_lead_id,
                Project.team_lead_id == current_user.id
            ),
            or_(
                Project.title.ilike(f"%{text}%"),
                Project.description.ilike(f"%{text}%")
            )
        ).all()
        ps = []
        for project in projects:
            data = {"project_title":project.title}
            data.update({"project_todos": Todo.query.filter_by(is_deleted = False, project_id = project.id).all()})
            ps.append(data)
        return render_template('admin/todo_projects.html', projects = ps)
    else:
        abort(403)