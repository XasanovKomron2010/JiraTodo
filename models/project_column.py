from models import db

class ProjectColumn(db.Model):
    __tablename__ = 'project_column'

    id = db.Column(db.Integer(), primary_key=True)
    column = db.Column(db.String(), nullable=False)
    order = db.Column(db.Integer(), nullable=False)
    is_deleted = db.Column(db.Boolean(), default=False)

    def __init__(self, column: str, order: int):
        super().__init__()
        self.column = column
        self.order = order