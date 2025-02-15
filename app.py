# -*- coding: utf-8 -*-

# Author: Rud Oleg
# Created: 25-November-2024
#
# License: MIT License
#
# Usage: flask run --host=0.0.0.0

# Dependencies:
# - flask
# - bootstrap5
# - sqlalchemy

# Version Information: 1.0

from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, logout_user
from flask_bootstrap import Bootstrap5
from sqlalchemy import func
import socket
import requests
import time
import smtplib
from email.mime.text import MIMEText
from database import init_db, ServiceStatus, db, User, Service
from forms import RegistrationForm, LoginForm, AddServiceForm, EditServiceForm
from flask_login import login_user, current_user, LoginManager
from apscheduler.schedulers.background import BackgroundScheduler
from location import get_location
from urllib.parse import urlparse
import configparser
import os


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///services.db'
init_db(app)
bootstrap = Bootstrap5(app)
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
config = configparser.ConfigParser()
config['SMTP'] = {
    'e-mail': 'your-email@example.com',
    'password': '<PASSWORD>',
    'server': 'smtp.example.com',
    'port': '587'
}
config['Schedule'] = {
    'interval': '300' # Set the interval in seconds to request updated data
}
config['Secret key'] = {
    'key': 'your_secret_key'
}
config_path = 'conf/config.ini'
os.makedirs(os.path.dirname(config_path), exist_ok=True)

if not os.path.exists(config_path):
    with open(config_path, 'w') as f:
        config.write(f)
    print("The configuration file is missing. A standard configuration file has been created")
else:
    config.read('conf/config.ini')
    print("The configuration file was successfully read")

app.config['SECRET_KEY'] = config['Secret key']['key']
schedule_interval = int(config['Schedule']['interval'])
DEFAULT_ERROR_RESPONSE_TIME = 9999.99
ERROR_TTL = 300

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class CheckServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def get_port_status(self) -> (str, int):
        """
        Check if a specific port is open on a given host.

        Args:
            host (str): The host to check.
            port (int): The port to check.

        Returns:
            bool: True if the port is open, False otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # timeout in seconds
        status = None
        try:
            start_time = time.time()
            result = sock.connect_ex((self.host, self.port))
            response_time = (time.time() - start_time) * 1000
            if result == 0:
                status = 'online'
            return status, response_time
        except socket.error as e:
            print(f"Error: {e}")
            response_time = DEFAULT_ERROR_RESPONSE_TIME
            return 'offline', response_time
        finally:
            sock.close()

    def get_web_code(self) -> (str, int, int):
        """
        Check the status of a web server.

        Args:
            url (str): The URL of the web server to check.

        Returns:
            int: The status code of the web page.
        """
        status = None
        try:
            if self.port == 443:
                start_time = time.time()
                response = requests.get('https://' + self.host, timeout=5)
                response_time = (time.time() - start_time) * 1000
                if response.status_code == 200:
                    status = 'online'
                return status, response_time, response.status_code
            else:
                start_time = time.time()
                response = requests.get('http://' + self.host + ':' + str(self.port), timeout=5)
                response_time = (time.time() - start_time) * 1000
                if response.status_code == 200:
                    status = 'online'
                return status, response_time, response.status_code
        except Exception as e:
            print(f"The waiting time for a response from the {self.host} has exceeded. - Error: {e}")
            status = 'offline'
            response_time = DEFAULT_ERROR_RESPONSE_TIME
            return status, response_time, 500

def check_services() -> None:
    """
    Check the status of all services in the database.

    This function retrieves all services from the database and checks their status by attempting to connect to their URLs.
    It also retrieves geolocation information for each service and stores the status and geolocation information in the database.

    Returns:
        None
    """
    with app.app_context():
        services = Service.query.with_entities(Service.service_name, Service.service_url, Service.id, Service.user_id).all()
        for service in services:
            service_name, service_url, service_id, user_id = service
            try:
                parsed = urlparse(str(service_url))
                if not parsed.scheme:
                    parsed = urlparse(f"http://{service_url}")

                if parsed.port:
                    host, port = parsed.hostname, parsed.port
                    checking_server = CheckServer(host, port)
                    status, response_time = checking_server.get_port_status()
                elif parsed.scheme != 'https' and parsed.scheme != 'http':
                    host, port = parsed.scheme, parsed.path
                    checking_server = CheckServer(host, int(port))
                    status, response_time = checking_server.get_port_status()
                else:
                    host, port = parsed.hostname, 80 if parsed.scheme == "http" else 443
                    checking_server = CheckServer(host, port)
                    status, response_time, status_code = checking_server.get_web_code()

            except Exception as e:
                status = 'offline'
                response_time = DEFAULT_ERROR_RESPONSE_TIME
                app.logger.error(f"The waiting time for a response from the {host} has exceeded. {e}")

            try:
                location_info = get_location(host)
                if "error" in location_info and (time.time() - location_info["timestamp"]) > ERROR_TTL:
                    get_location.cache_clear()  # Reset cache for this host
            except Exception as e:
                location_info = {
                    "query": host,
                    "countryCode": "N/A",
                    "region": "N/A",
                    "city": "N/A",
                    "isp": "N/A",
                    "timezone": "N/A"
                }
                app.logger.error(f"Geolocation request failed. {e}")

            service_status = ServiceStatus(
                service_name=service_name,
                service_url=service_url,
                service_ip=location_info.get('query', 'N/A'),
                service_location=f"{location_info.get('countryCode', 'N/A')} {location_info.get('region', 'N/A')} {location_info.get('city', 'N/A')}",
                service_isp=location_info.get('isp', 'N/A'),
                service_timezone=location_info.get('timezone', 'N/A'),
                status=status,
                response_time=response_time,
                user_id=user_id,
                service_id=service_id,
                status_code=status_code
            )
            db.session.add(service_status)
        db.session.commit()
        monitor_services()


def check_user_services() ->  list[dict[str, str | None]]:
    """
    Check the status of all services for the current user.

    This function retrieves all services associated with the current user from the database and checks their status by attempting to connect to their URLs.
    It also retrieves geolocation information for each service and stores the status and geolocation information in the database.

    Returns:
        list: A list of dictionaries containing the status and geolocation information for each service.
    """
    results = []
    services = Service.query.filter_by(user_id=current_user.id).with_entities(Service.service_name, Service.service_url,
                                                                              Service.id).all()
    for service in services:
        service_name, service_url, service_id = service
        try:
            parsed = urlparse(str(service_url))
            print(parsed.path)
            if not parsed.scheme:
                parsed = urlparse(f"http://{service_url}")

            if parsed.port:
                host, port = parsed.hostname, parsed.port
                checking_server = CheckServer(host, port)
                status, response_time = checking_server.get_port_status()
            elif parsed.scheme != 'https' and parsed.scheme != 'http':
                host, port = parsed.scheme, int(parsed.path)
                checking_server = CheckServer(host, port)
                status, response_time = checking_server.get_port_status()
            else:
                host, port = parsed.hostname, 80 if parsed.scheme == "http" else 443
                checking_server = CheckServer(host, port)
                status, response_time, status_code = checking_server.get_web_code()

        except Exception as e:
            status = 'offline'
            response_time = DEFAULT_ERROR_RESPONSE_TIME
            app.logger.error(f"The waiting time for a response from the {host} has exceeded. {e}")

        # Getting geolocation with error handling
        try:
            location_info = get_location(host)
            if "error" in location_info and (time.time() - location_info["timestamp"]) > ERROR_TTL:
                get_location.cache_clear(host)  # Reset cache for this host
        except Exception as e:
            location_info = {
                "query": host,
                "countryCode": "N/A",
                "region": "N/A",
                "city": "N/A",
                "isp": "N/A",
                "timezone": "N/A"
            }
            app.logger.error(f"Geolocation request failed. {e}")

        results.append({
            "service_name": service_name,
            "service_url": service_url,
            "status": status,
            "response_time": f"{response_time:.2f} ms",
            "service_location": f"{location_info.get('countryCode', 'N/A')} {location_info.get('region', 'N/A')} {location_info.get('city', 'N/A')}",
            "service_isp": location_info.get('isp', 'N/A'),
            "service_timezone": location_info.get('timezone', 'N/A'),
            "status_code": status_code
        })
        service_status = ServiceStatus(
            service_name=service_name,
            service_url=service_url,
            service_ip=location_info.get('query', 'N/A'),
            service_location=f"{location_info.get('countryCode', 'N/A')} {location_info.get('region', 'N/A')} {location_info.get('city', 'N/A')}",
            service_isp=location_info.get('isp', 'N/A'),
            service_timezone=location_info.get('timezone', 'N/A'),
            status=status,
            response_time=response_time,
            user_id=current_user.id,
            service_id=service_id,
            status_code=status_code
        )
        db.session.add(service_status)
        db.session.commit()
    return results


def send_email(subject: str, message: str, user_email: str) -> None:
    """
    Send an email to a specified user.

    Args:
        subject (str): The subject of the email.
        message (str): The body of the email.
        user_email (str): The email address of the recipient.

    Returns:
        None
    """
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = config['SMTP']['e-mail']
    msg['To'] = user_email[0]

    with smtplib.SMTP(config['SMTP']['server'], int(config['SMTP']['port'])) as server:
        server.starttls()
        server.login(config['SMTP']['e-mail'], config['SMTP']['password'])
        server.sendmail(msg['From'], [msg['To']], msg.as_string())


def get_last_status(service_url: str) -> tuple[str, str]:
    """
    Get the last status of a service.

    Args:
        service_url (str): The URL of the service.

    Returns:
        tuple[str, str]: A tuple containing the last status and the current status of the service.
    """
    current_status = ServiceStatus.query.filter_by(service_url=service_url).order_by(
        ServiceStatus.timestamp.desc()).first()
    last_status = ServiceStatus.query.filter_by(service_url=service_url).order_by(
        ServiceStatus.timestamp.desc()).offset(1).first()

    return last_status.status, current_status.status if last_status else None


def monitor_services() -> None:
    """
    Monitor the status of all services and send email notifications if there is a change in status.

    This function retrieves all services from the database and checks their status by attempting to connect to their URLs.
    If there is a change in status, it sends an email notification to the user associated with the service.

    Returns:
        None
    """
    with app.app_context():
        services = Service.query.with_entities(Service.service_name, Service.service_url, Service.id,
                                               Service.user_id).all()
        for service in services:
            service_name, service_url, service_id, user_id = service
            user_email = User.query.filter_by(id=user_id).with_entities(User.email).one()
            last_status, current_status = get_last_status(service_url)
            if last_status != current_status and last_status is not None:
                if current_status == 'offline':
                    try:
                        send_email(f"Service {service_name} is now offline", f"The service {service_url} has gone offline at {time.strftime('%Y-%m-%d %H:%M:%S')}", user_email)
                    except Exception as e:
                        app.logger.error(f"Failed to send email: {e}")
                else:
                    try:
                        send_email(f"Service {service_name} is now online", f"The service {service_url} is now online at {time.strftime('%Y-%m-%d %H:%M:%S')}", user_email)
                    except Exception as e:
                        app.logger.error(f"Failed to send email: {e}")


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

@app.route('/change_settings', methods=['GET', 'POST'])
@login_required
def change_settings():
    if request.method == 'POST':
        password = request.form.get('password')
        email = request.form.get('email')

        user_id = current_user.id
        user = User.query.get(user_id)

        if user:
            if password:
                user.set_password(password)
            if email:
                user.email = email

            db.session.commit()
            flash('You have successfully change settings')
            return redirect(url_for('change_settings'))

    return render_template('change_settings.html', schedule_interval=schedule_interval)

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
    subquery = (ServiceStatus.query
                .with_entities(ServiceStatus.service_url,
                               func.max(ServiceStatus.timestamp).label('max_timestamp'))
                .group_by(ServiceStatus.service_url).filter_by(user_id=current_user.id)
                ).subquery()

    services = ServiceStatus.query.filter_by(user_id=current_user.id).join(subquery,
                                        (ServiceStatus.service_url == subquery.c.service_url) &
                                        (ServiceStatus.timestamp == subquery.c.max_timestamp))

    services_sla = ServiceStatus.query.filter(ServiceStatus.user_id == current_user.id).all()
    total_responses_per_service = {s.service_url: len([ss for ss in services_sla if ss.service_url == s.service_url])
                                   for s in services}

    online_count_per_service = {
        s.service_url: sum(1 for ss in services_sla if ss.status == 'online' and ss.service_url == s.service_url) for s
        in services}
    sla_results = {service_url: round((online_count / total_responses) * 100, 2) if total_responses > 0 else 0
                   for service_url, online_count in online_count_per_service.items()
                   for total_responses in [total_responses_per_service[service_url]]}

    average_response_time_per_service = {s.service_url: sum(ss.response_time for ss in services_sla if
                                         ss.service_url == s.service_url and ss.response_time is not None
                                         and ss.response_time < DEFAULT_ERROR_RESPONSE_TIME) / len(
        [ss for ss in services_sla if ss.service_url == s.service_url and ss.response_time is not None
         and ss.response_time < DEFAULT_ERROR_RESPONSE_TIME])
    if any(ss.response_time is not None for ss in services_sla if ss.service_url == s.service_url) else None
                                         for s in services}

    return render_template('index.html', services=services,
                           total_responses_per_service=total_responses_per_service,
                           online_count_per_service=online_count_per_service, sla_results=sla_results,
                           average_response_time_per_service=average_response_time_per_service)

@app.route('/service_management', methods=['GET'])
@login_required
def service_management():
    services_user = Service.query.filter_by(user_id=current_user.id).with_entities(Service.id,
                                                                                   Service.service_name,
                                                                                   Service.service_url,
                                                                                   Service.description).all()
    return render_template('service_management.html', services_user=services_user)


@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    form = AddServiceForm()

    existing_services_count = Service.query.filter_by(user_id=current_user.id).count()

    if existing_services_count >= 10:
        flash('You have reached the maximum number of services allowed.', 'error')
        return redirect(url_for('service_management'))

    if form.validate_on_submit():
        service = Service(service_name=form.service_name.data,
                          service_url=form.service_url.data,
                          description=form.description.data,
                          user_id=current_user.id)
        db.session.add(service)
        db.session.commit()
        check_services_route()
        flash('Your service has been added!', 'success')
        return redirect(url_for('service_management'))

    return render_template('add_service.html', title='Add Service', form=form)

@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    form = EditServiceForm(obj=service)
    if form.validate_on_submit():
        service.service_name = form.service_name.data
        service.service_url = form.service_url.data
        service.description = form.description.data
        db.session.commit()
        flash('Your changes have been saved!', 'success')
        return redirect(url_for('service_management'))
    elif request.method == 'GET':
        form.service_name.data = service.service_name
        form.service_url.data = service.service_url
        form.description.data = service.description
    return render_template('edit_service.html', title='Edit Service', form=form)

@app.route('/delete_service/<int:service_id>', methods=['POST'])
@login_required
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    if service.user_id != current_user.id:
        abort(403)  # Forbidden access
    ServiceStatus.query.filter_by(service_id=service_id).delete(synchronize_session=False)
    db.session.delete(service)
    db.session.commit()
    flash('Your service has been deleted!', 'success')
    return redirect(url_for('service_management'))

@app.route('/check_services', methods=['GET'])
@login_required
def check_services_route():
    """
    Check the status of all services for the current user.

    This function retrieves all services associated with the current user from the database and checks their status by attempting to connect to their URLs.
    It also retrieves geolocation information for each service and stores the status and geolocation information in the database.

    Returns:
        Response: A JSON response containing the status and geolocation information for each service.
    """
    with app.app_context():
        return jsonify(check_user_services())

scheduler = BackgroundScheduler()
scheduler.add_job(func=check_services, trigger='interval', seconds=schedule_interval)
scheduler.start()

@app.route('/sla', methods=['GET'])
@login_required
def sla():
    services = ServiceStatus.query.all()
    total_responses = len(services)
    online_count = sum(1 for s in services if s.status == 'online')

    if total_responses > 0:
        sla_result = (online_count / total_responses) * 100
    else:
        sla_result = 0

    average_response_time = sum(s.response_time for s in services if s.response_time is not None) / len(
        [s for s in services if s.response_time is not None]) if any(
        s.response_time is not None for s in services) else None

    return jsonify({
        "total_responses": total_responses,
        "online_count": online_count,
        "sla": f"{sla_result:.2f}%",
        "average_response_time": f"{average_response_time:.2f} ms" if average_response_time is not None else None
    })


if __name__ == '__main__':
    app.run(debug=True)