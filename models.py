from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy.orm import validates
from database import db

class ServiceStatus(db.Model):
    """
    A model for storing the status of a service.

    Attributes:
        id (int): The primary key of the service status.
        service_name (str): The name of the service.
        service_url (str): The URL of the service.
        service_ip (str): The IP address of the service.
        service_location (str): The location of the service.
        service_isp (str): The ISP of the service.
        service_timezone (str): The timezone of the service.
        status (str): The status of the service.
        response_time (float): The response time of the service.
        timestamp (datetime): The timestamp of the service status.
        last_status_change (datetime): The timestamp of the last status change.
        user_id (int): The ID of the user associated with the service.
        service_id (int): The ID of the service.
        status_code (int): The status code of the service.
    """
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(255), nullable=False, unique=False)
    service_url = db.Column(db.String(255), nullable=False, unique=False)
    service_ip = db.Column(db.String(255), nullable=False, unique=False)
    service_location = db.Column(db.String(255), nullable=False, unique=False)
    service_isp = db.Column(db.String(255), nullable=False, unique=False)
    service_timezone = db.Column(db.String(255), nullable=False, unique=False)
    status = db.Column(db.String(10), nullable=False)
    response_time = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_status_change = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)

class User(UserMixin, db.Model):
    """
    A model for storing user information.

    Attributes:
        id (int): The primary key of the user.
        username (str): The username of the user.
        email (str): The email address of the user.
        password_hash (str): The hashed password of the user.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        """
        Set the password for the user.

        This function sets the password for the user by hashing the provided password and storing the hash in the password_hash attribute.

        Args:
            password (str): The password to set for the user.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Check the password for the user.

        This function checks the provided password against the stored password hash.

        Args:
            password (str): The password to check for the user.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        return check_password_hash(self.password_hash, password)
    @validates('polling_interval')
    def validate_polling_interval(self, key, polling_interval):
        """
        Validate the polling interval for the user.

        This function validates the polling interval for the user. The polling interval must be between 120 and 3600 seconds.

        Args:
            key (str): The key of the attribute being validated.
            polling_interval (int): The polling interval to validate.

        Raises:
            AssertionError: If the polling interval is not between 120 and 3600 seconds.
        """
        assert 120 >= polling_interval <= 3600

class Service(db.Model):
    """
    A model for storing service information.

    Attributes:
        id (int): The primary key of the service.
        service_name (str): The name of the service.
        service_url (str): The URL of the service.
        description (str): A description of the service.
        user_id (int): The ID of the user associated with the service.
    """
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(50), nullable=False, unique=False)
    service_url = db.Column(db.String(255), nullable=False, unique=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        """
        Return a string representation of the service.

        Returns:
            str: A string representation of the service.
        """
        return f'<Service {self.service_name}>'