from flask_login import UserMixin
from models import db, login_manager
from flask_bcrypt import generate_password_hash

@login_manager.user_loader
def load_user(user_id: int):
    return User.query.filter_by(id = user_id, is_deleted = False).first()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer(), primary_key=True)
    team_lead_id = db.Column(db.Integer(), db.ForeignKey('users.id'), nullable=True)
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id'), nullable = True)
    full_name = db.Column(db.String(), nullable = False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique = True, nullable = False)
    is_deleted = db.Column(db.Boolean(), default = False)

    def __init__(self, team_lead_id: int, full_name: str, username: str, password: str, email: str, role):
        self.team_lead_id = team_lead_id
        self.full_name = full_name
        self.username = username
        self.password = generate_password_hash(password).decode('utf-8')
        self.email = email
        self.role_id = role