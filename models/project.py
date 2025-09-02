from models import db
from datetime import datetime

class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer(), primary_key=True)
    team_lead_id = db.Column(db.Integer(), db.ForeignKey('users.id'), nullable=True)
    title = db.Column(db.String(), nullable=False)
    description = db.Column(db.String(), nullable=True)
    deadline = db.Column(db.DateTime(), nullable=False)
    is_frozen = db.Column(db.Boolean(), default=False)
    is_deleted = db.Column(db.Boolean(), default=False)
    created_at = db.Column(db.DateTime(), default=datetime.now())

    def __init__(self, team_lead_id: int, title: str, description: str, deadline: datetime):
        self.team_lead_id = team_lead_id
        self.title = title
        self.description = description
        self.deadline = deadline
    