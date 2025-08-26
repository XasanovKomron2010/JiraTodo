from flask import render_template, redirect, url_for, flash, abort
from flask_login import login_user, logout_user, login_required
from forms.auth_forms import LoginForm, RegisterForm
from flask_bcrypt import check_password_hash
from models.user import User
from models.role import Role
from models import db
from app import root

@root.route('/register', methods = ['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        full_name = form.full_name.data
        username = form.username.data
        password = form.password.data
        email = form.email.data

        user = User.query.filter_by(username=username).first()
        if user is None:
            new_user = User(team_lead_id=None, full_name = full_name, username = username, password = password, email=email)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))
        else:
            flash("There is already another user with the same username, try the other one", "danger")
            return redirect(url_for('register_page'))
    else:
        return render_template('auth/register.html', form=form)

@root.route('/login', methods = ['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user is not None and check_password_hash(user.password, password):
            role = Role.query.filter_by(is_deleted = False, id = user.role_id).first().role
            if role == 'employee':
                login_user(user)
                return redirect(url_for('home_page'))
            elif role == 'admin' or role == 'team-lead':
                login_user(user)
                return redirect(url_for('admin_page'))
        else:
            flash("We do not have such a user, check your username and password", 'danger')
            return redirect(url_for('login_page'))
    else:
        return render_template('auth/login.html', form=form)

@root.route('/logout', methods = ['GET'])
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('login_page'))