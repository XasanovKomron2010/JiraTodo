from models import db

class Permission(db.Model):
    __tablename__ = 'permissions'

    id = db.Column(db.Integer(), primary_key = True)
    permission = db.Column(db.String(), nullable = False)
    is_deleted = db.Column(db.Boolean(), default = False)

    def __init__(self, permission: str):
        super().__init__()
        self.permission = permission