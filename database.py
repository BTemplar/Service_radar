from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy.orm import validates

db = SQLAlchemy()

class ServiceStatus(db.Model):
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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    @validates('polling_interval')
    def validate_polling_interval(self, key, polling_interval):
        assert 120 >= polling_interval <= 3600

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(50), nullable=False, unique=False)
    service_url = db.Column(db.String(255), nullable=False, unique=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Service {self.service_name}>'

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()