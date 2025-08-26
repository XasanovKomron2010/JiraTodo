from models import db

class RolePermission(db.Model):
    __tablename__ = 'role_permission'

    id = db.Column(db.Integer(), primary_key = True)
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id'), nullable = False)
    permission_id = db.Column(db.Integer(), db.ForeignKey('permissions.id'), nullable = False)
    is_deleted = db.Column(db.Boolean(), default = False)

    def __init__(self, role_id: int, permission_id: int):
        super().__init__()
        self.role_id = role_id
        self.permission_id = permission_id