from flask_wtf import FlaskForm
from database import User
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, validators
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AddServiceForm(FlaskForm):
    service_name = StringField('Service name', validators=[DataRequired(), Length(max=30)])
    service_url = StringField('Service url/ip:port', validators=[DataRequired(), Length(max=30)])
    description = TextAreaField('Description', validators=[Length(max=30)])
    submit = SubmitField('Add Service')

class EditServiceForm(FlaskForm):
    service_name = StringField('Service name', validators=[DataRequired(), Length(max=30)])
    service_url = StringField('Service url/ip:port', validators=[DataRequired(), Length(max=30)])
    description = TextAreaField('Description', validators=[Length(max=30)])
    submit = SubmitField('Save')

    def __init__(self, *args, **kwargs):
        super(EditServiceForm, self).__init__(*args, **kwargs)

class ChangePasswordForm(FlaskForm):
    change_password = BooleanField('Change Password')
    new_password = PasswordField(
        'New Password',
        validators=[
            Length(min=8, message="Password must be at least 8 characters"),
            validators.Regexp(r'(?=.*[0-9])', message="Password must contain at least one digit."),
            validators.Regexp(r'(?=.*[A-Z])', message="Password must contain at least one uppercase letter."),
            validators.Regexp(r'(?=.*[a-z])', message="Password must contain at least one lowercase letter.")
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            EqualTo('new_password', message='Passwords do not match')
        ]
    )


class ChangeEmailForm(FlaskForm):
    change_email = BooleanField('Change Email')
    email = StringField(
        'New Email',
        validators=[
            Email(message="Invalid email format")
        ]
    )