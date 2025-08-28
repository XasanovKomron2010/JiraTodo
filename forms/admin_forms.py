from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, validators, SelectField, DateTimeLocalField, IntegerField


class UserCreateForm(FlaskForm):
    full_name = StringField("Full Name", [validators.DataRequired()])
    team_lead = SelectField("Team Lead", choices = [])
    username = StringField("Username", [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired(), validators.Length(min=8, max=30)])
    role = SelectField("Role", choices = [])
    email = EmailField("Email", [validators.DataRequired()])
    submit = SubmitField('Create User')

    def __init__(self, team_leads, roles, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.team_lead.choices = [(None, "Nobody")] + [(t.id, t.full_name) for t in team_leads]
        self.role.choices = [(r.role.lower(), r.role.title()) for r in roles]

class ProjectCreateForm(FlaskForm):
    team_lead = SelectField("Team Lead", choices = [])
    title = StringField("Title", [validators.DataRequired()])
    description = StringField("Description", [validators.DataRequired()])
    deadline = DateTimeLocalField("Deadline", format='%Y-%m-%dT%H:%M', validators=[validators.DataRequired()])
    status = SelectField("Column", choices = [])
    submit = SubmitField("Submit", [validators.DataRequired()])

    def __init__(self, team_leads, column_choices, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.team_lead.choices = [(None, "Nobody")] + [(t.id, t.full_name) for t in team_leads]
        self.status.choices = [(cc.id, cc.column) for cc in column_choices]

class TodoCreateForm(FlaskForm):
    user_id = SelectField("User", choices = [])
    project_id = SelectField("Project", choices = [])
    title = StringField("Title", [validators.DataRequired()])
    description = StringField("Description", [validators.DataRequired()])
    priority = SelectField('Priority', choices=[('low','Low'),('medium','Medium'),('high','High')], default='low')
    status = SelectField('Status', choices = [('pending','Pending'),('doing','Doing'),('completed','Completed'),('failed','Failed')])
    deadline = DateTimeLocalField("Deadline", format='%Y-%m-%dT%H:%M', validators=[validators.DataRequired()])
    submit = SubmitField("Create Todo")

    def __init__(self, users, projects, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_id.choices = [(None, 'Nobody')] + [(u.id, u.full_name) for u in users]
        self.project_id.choices = [(None, 'Nothing')] + [(p.id, p.title) for p in projects]

class ProjectColumnCreateForm(FlaskForm):
    column = StringField("Column", [validators.DataRequired()])
    order = IntegerField("Order", [validators.DataRequired()])
    submit = SubmitField("Submit")