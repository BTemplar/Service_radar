from flask import Flask, jsonify, render_template, redirect, url_for, request, flash
from flask_login import login_required, logout_user
import requests
import socket
import time
import smtplib
from email.mime.text import MIMEText
from database import init_db, ServiceStatus, db, User
from forms import RegistrationForm, LoginForm
from flask_login import login_user, current_user, LoginManager
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///services.db'
init_db(app)

SERVICES = [
    ['example', 'https://example.com'],
    ['127.0.0.1','127.0.0.1:37']
] # Your services name and services here


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # timeout in seconds
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except socket.error as e:
        print(f"Error: {e}")
        return False
    finally:
        sock.close()

def check_services():
    results = []
    for service_url in SERVICES:
        if '://' not in service_url[1] and ':' in service_url[1]:
            start_time = time.time()
            host, port = service_url[1].split(':')
            port = int(port)
            status = 'online' if check_port(host, port) else 'offline'
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
        else:
            try:
                start_time = time.time()
                end_time = time.time()
                response_time = (end_time - start_time) * 1000
                status = 'online'
            except requests.RequestException as e:
                response_time = None
                status = 'offline'
        if status == 'offline':
            response_time = 9999.99
        service_status = ServiceStatus(
            service_name=service_url[0],
            service_url=service_url[1],
            status=status,
            response_time=response_time
        )
        db.session.add(service_status)
        results.append({
            "service_name": service_url[0],
            "service_url": service_url[1],
            "status": status,
            "response_time": f"{response_time:.2f} ms" if response_time is not None else None
        })
    db.session.commit()

    return results

def send_email(subject, message):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = 'your-email@example.com'
    msg['To'] = 'recipient-email@example.com'

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login(msg['From'], 'your-email-password')
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

def get_last_status(service_url):
    last_status = ServiceStatus.query.filter_by(service_url=service_url).order_by(ServiceStatus.timestamp.desc()).first()
    return last_status.status if last_status else None

def monitor_services():
    with app.app_context():
        current_statuses = check_services()
        for service_url, current_status in zip(SERVICES, current_statuses):
            last_status = get_last_status(service_url[1])
            if last_status != current_status['status']:
                if current_status['status'] == 'offline':
                    send_email(f"Service {service_url[0]} is offline", f"The service {service_url[0]} has gone offline at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                else:
                    send_email(f"Service {service_url[0]} is online", f"The service {service_url[0]} is now online at {time.strftime('%Y-%m-%d %H:%M:%S')}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists')
            return redirect(url_for('register'))

        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('You have successfully registered')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
@login_required
def index():
    services = ServiceStatus.query.order_by(ServiceStatus.timestamp.desc()).group_by(ServiceStatus.service_url).all()
    services_sla = ServiceStatus.query.all()
    total_responses = len(services_sla)
    online_count = sum(1 for s in services_sla if s.status == 'online')

    if total_responses > 0:
        sla = round((online_count / total_responses) * 100, 2)
    else:
        sla = 0

    average_response_time = sum(s.response_time for s in services_sla if s.response_time is not None) / len([s for s in services_sla if s.response_time is not None]) if any(s.response_time is not None for s in services_sla) else None

    return render_template('index.html', services=services, total_responses=total_responses, online_count=online_count, sla=f"{sla:.2f}%", average_response_time=f"{average_response_time:.2f} ms" if average_response_time is not None else None)

@app.route('/check_services', methods=['GET'])
@login_required
def check_services_route():
    with app.app_context():
        return jsonify(check_services())

scheduler = BackgroundScheduler()
scheduler.add_job(func=monitor_services, trigger='interval', seconds=300) # Set the interval in seconds to request updated data
scheduler.start()

@app.route('/sla', methods=['GET'])
@login_required
def sla():
    services = ServiceStatus.query.all()
    total_responses = len(services)
    online_count = sum(1 for s in services if s.status == 'online')

    if total_responses > 0:
        sla = (online_count / total_responses) * 100
    else:
        sla = 0

    average_response_time = sum(s.response_time for s in services if s.response_time is not None) / len(
        [s for s in services if s.response_time is not None]) if any(
        s.response_time is not None for s in services) else None

    return jsonify({
        "total_responses": total_responses,
        "online_count": online_count,
        "sla": f"{sla:.2f}%",
        "average_response_time": f"{average_response_time:.2f} ms" if average_response_time is not None else None
    })


if __name__ == '__main__':
    app.run(Debug=True)