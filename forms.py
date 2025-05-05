from flask_wtf import FlaskForm
from models import User
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, validators
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError

class RegistrationForm(FlaskForm):
    """
    A form for registering a new user.

    Attributes:
        username (StringField): A string field for entering the username.
        email (StringField): A string field for entering the email address.
        password (PasswordField): A password field for entering the password.
        confirm_password (PasswordField): A password field for confirming the password.
        submit (SubmitField): A submit field for submitting the form.
    """
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username: str) -> str:
        """
        Validate the username field.

        This function checks if the username already exists in the database.
        If the username already exists, it raises a ValidationError.

        Args:
            username (StringField): The username field to validate.

        Raises:
            ValidationError: If the username already exists in the database.
        """
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email: str) -> str:
        """
        Validate the email field.

        This function checks if the email address already exists in the database.
        If the email address already exists, it raises a ValidationError.

        Args:
            email (StringField): The email field to validate.

        Raises:
            ValidationError: If the email address already exists in the database.
        """
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one.')

class LoginForm(FlaskForm):
    """
    A form for logging in a user.

    Attributes:
        username (StringField): A string field for entering the username.
        password (PasswordField): A password field for entering the password.
        remember_me (BooleanField): A boolean field for indicating whether the user wants to be remembered.
        submit (SubmitField): A submit field for submitting the form.
    """
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AddServiceForm(FlaskForm):
    """
    A form for adding a new service.

    Attributes:
        service_name (StringField): A string field for entering the service name.
        service_url (StringField): A string field for entering the service URL or IP address and port.
        description (TextAreaField): A text area field for entering a description of the service.
        submit (SubmitField): A submit field for submitting the form.
    """
    service_name = StringField('Service name', validators=[DataRequired(), Length(max=30)])
    service_url = StringField('Service url/ip:port', validators=[DataRequired(), Length(max=30)])
    description = TextAreaField('Description', validators=[Length(max=30)])
    submit = SubmitField('Add Service')

class EditServiceForm(FlaskForm):
    """
    A form for editing a service.

    Attributes:
        service_name (StringField): A string field for entering the service name.
        service_url (StringField): A string field for entering the service URL or IP address and port.
        description (TextAreaField): A text area field for entering a description of the service.
        submit (SubmitField): A submit field for submitting the form.
    """
    service_name = StringField('Service name', validators=[DataRequired(), Length(max=30)])
    service_url = StringField('Service url/ip:port', validators=[DataRequired(), Length(max=30)])
    description = TextAreaField('Description', validators=[Length(max=30)])
    submit = SubmitField('Save')

    def __init__(self, *args, **kwargs):
        super(EditServiceForm, self).__init__(*args, **kwargs)

class ChangePasswordForm(FlaskForm):
    """
    A form for changing a user's password.

    Attributes:
        change_password (BooleanField): A boolean field for indicating whether the user wants to change their password.
        new_password (PasswordField): A password field for entering the new password.
        confirm_password (PasswordField): A password field for confirming the new password.
    """
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
    """
    A form for changing a user's email address.

    Attributes:
        change_email (BooleanField): A boolean field for indicating whether the user wants to change their email address.
        email (StringField): A string field for entering the new email address.
    """
    change_email = BooleanField('Change Email')
    email = StringField(
        'New Email',
        validators=[
            Email(message="Invalid email format")
        ]
    )