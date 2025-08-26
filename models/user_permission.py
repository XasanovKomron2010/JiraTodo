from models import db

class UserPermission(db.Model):
    __tablename__ = 'user_permission'

    id = db.Column(db.Integer(), primary_key = True, autoincrement = True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'), nullable = False)
    permission_id = db.Column(db.Integer(), db.ForeignKey('permissions.id'), nullable = False)
    is_deleted = db.Column(db.Boolean(), default = False)

    def __init__(self, user_id: int, permission_id: int):
        super().__init__()
        self.user_id = user_id
        self.permission_id = permission_id