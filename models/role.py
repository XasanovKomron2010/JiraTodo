from models import db

class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer(), primary_key = True)
    role = db.Column(db.String(), nullable = False)
    is_deleted = db.Column(db.Boolean(), default = False)

    def __init__(self, role: str):
        super().__init__()
        self.role = role