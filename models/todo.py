from models import db
from datetime import datetime

class Todo(db.Model):
    __tablename__ = 'todos'

    id = db.Column(db.Integer(), primary_key = True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'), nullable = True)
    column_id = db.Column(db.Integer(), db.ForeignKey('project_column.id'), nullable = True)
    title = db.Column(db.String(), nullable = False)
    description = db.Column(db.String(), nullable = True)
    priority = db.Column(db.String(), default='low')
    deadline = db.Column(db.DateTime(), nullable = False)
    user_status = db.Column(db.String(), default='pending')
    is_frozen = db.Column(db.Boolean(), default = False)
    is_deleted = db.Column(db.Boolean(), default = False)
    created_at = db.Column(db.DateTime(), default = datetime.now())

    def __init__(self, user_id: int, title: str, description: str, deadline: datetime, priority: str = 'low', column_id: int = None):
        super().__init__()
        self.user_id = user_id
        self.title = title
        self.description = description
        self.deadline = deadline
        self.priority = priority
        self.column_id = column_id