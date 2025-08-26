from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, validators

class RegisterForm(FlaskForm):
    full_name = StringField("Full Name", [validators.DataRequired()])
    username = StringField("Username", [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired(), validators.Length(min=8, max=30)])
    email = EmailField("Email", [validators.DataRequired()])
    submit = SubmitField('Login')

class LoginForm(FlaskForm):
    username = StringField("Username", [validators.DataRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired(), validators.Length(min=8, max=30)])
    submit = SubmitField('Login')