from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ServiceStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(255), nullable=False)
    service_url = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    response_time = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    __table_args__ = (
        db.UniqueConstraint('service_name', 'service_url', 'timestamp', name='uix_service_url_timestamp'),
    )

def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()