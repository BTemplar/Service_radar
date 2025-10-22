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
# - flask-login
# - apscheduler
# - requests
# - python-dotenv (for environment variables)

import os
import time
import socket
import smtplib
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from typing import Optional, Tuple, Dict

import requests
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, abort
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_bootstrap import Bootstrap5
from sqlalchemy import func
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from database import init_db, db
from models import ServiceStatus, User, Service
from forms import RegistrationForm, LoginForm, AddServiceForm, EditServiceForm, ChangePasswordForm, ChangeEmailForm
from location import get_location
import configparser

# APP CONFIGURATION
app = Flask(__name__)

# Using environment variables or a config file
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///services.db'
app.config['BOOTSTRAP_SERVE_LOCAL'] = True

# Initializing extensions
init_db(app)
bootstrap = Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Setting up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@login_manager.user_loader
def load_user(user_id: int) -> Optional[User]:
    return User.query.get(int(user_id))


def load_or_create_config() -> configparser.ConfigParser:
    """Loads a configuration from a file or creates a new one with default values."""
    config_path = 'conf/config.ini'
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    config = configparser.ConfigParser()

    # Default values
    config['SMTP'] = {
        'email': os.environ.get('SMTP_EMAIL', 'your-email@example.com'),
        'password': os.environ.get('SMTP_PASSWORD', '<PASSWORD>'),
        'server': os.environ.get('SMTP_SERVER', 'smtp.example.com'),
        'port': os.environ.get('SMTP_PORT', '587')
    }
    config['Schedule'] = {
        'interval': os.environ.get('CHECK_INTERVAL', '300'),
        'retention_period': os.environ.get('RETENTION_DAYS', '30')
    }
    config['Secret key'] = {
        'key': 'your_secret_key'
    }

    if not os.path.exists(config_path):
        with open(config_path, 'w') as f:
            config.write(f)
        logger.info("Создан новый конфигурационный файл.")
    else:
        config.read(config_path)
        logger.info("Конфигурационный файл успешно загружен.")

    return config


config = load_or_create_config()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or config['Secret key']['key']
SCHEDULE_INTERVAL = int(config['Schedule']['interval'])
RETENTION_PERIOD = int(config['Schedule']['retention_period'])
DEFAULT_ERROR_RESPONSE_TIME = 9999.99
ERROR_TTL = 300


# AUXILIARY FUNCTIONS AND CLASSES
class CheckServer:
    """Class for checking server status by port or HTTP/HTTPS."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    def get_port_status(self) -> Tuple[Optional[str], float]:
        """Checks if a port is available for a socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            start_time = time.time()
            result = sock.connect_ex((self.host, self.port))
            response_time = (time.time() - start_time) * 1000
            if result == 0:
                return 'online', response_time
            else:
                return 'offline', DEFAULT_ERROR_RESPONSE_TIME
        except socket.error as e:
            logger.error(f"Ошибка сокета {self.host}:{self.port} - {e}")
            return 'offline', DEFAULT_ERROR_RESPONSE_TIME
        finally:
            sock.close()

    def get_web_status(self) -> Tuple[Optional[str], float, Optional[int]]:
        """Checks the availability of a web service via HTTP/HTTPS."""
        protocol = 'https' if self.port == 443 else 'http'
        base_url = f"{protocol}://{self.host}"
        if protocol == 'http' and self.port != 80:
            base_url += f":{self.port}"

        try:
            start_time = time.time()
            response = requests.get(base_url, timeout=5)
            response_time = (time.time() - start_time) * 1000
            status_code = response.status_code
            status = 'online' if status_code == 200 else 'offline'
            return status, response_time, status_code
        except requests.RequestException as e:
            logger.error(f"Ошибка HTTP-запроса для {base_url} - {e}")
            return 'offline', DEFAULT_ERROR_RESPONSE_TIME, 500


def parse_service_url(service_url: str) -> Tuple[str, int]:
    """Parses the service URL into host and port."""
    parsed = urlparse(str(service_url))
    if not parsed.scheme:
        parsed = urlparse(f"http://{service_url}")

    if parsed.port:
        host, port = parsed.hostname, parsed.port
    elif parsed.scheme in ('http', 'https'):
        host = parsed.hostname
        port = 80 if parsed.scheme == "http" else 443
    else:
        # Treat scheme as host and path as port (e.g. 'smtp.gmail.com/587')
        host, port_str = parsed.scheme, parsed.path.lstrip('/')
        try:
            port = int(port_str)
        except ValueError:
            logger.error(f"Неверный формат порта в URL: {service_url}")
            raise ValueError(f"Неверный формат порта в URL: {service_url}")

    return host, port


def get_or_create_location_info(host: str) -> Dict[str, str]:
    """Gets geolocation information, resets cache on error."""
    try:
        location_info = get_location(host)
        if "error" in location_info and (time.time() - location_info.get("timestamp", 0)) > ERROR_TTL:
            get_location.cache_clear()
            location_info = get_location(host)
    except Exception as e:
        logger.error(f"Geolocation request failed for {host}. {e}")
        location_info = {
            "query": host,
            "countryCode": "N/A",
            "region": "N/A",
            "city": "N/A",
            "isp": "N/A",
            "timezone": "N/A"
        }
    return location_info


def send_email_notification(subject: str, message: str, recipient_email: str) -> bool:
    """Sends an email notification."""
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = config['SMTP']['email']
        msg['To'] = recipient_email

        with smtplib.SMTP(config['SMTP']['server'], int(config['SMTP']['port'])) as server:
            server.starttls()
            server.login(config['SMTP']['email'], config['SMTP']['password'])
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Сбой при отрпавке пиьсма {recipient_email}: {e}")
        return False


def check_and_log_service_status(service: Tuple[str, str, int, int]) -> None:
    """Performs a health check on a single service and saves its status."""
    service_name, service_url, service_id, user_id = service
    host, port = parse_service_url(service_url)
    checker = CheckServer(host, port)

    if port in (80, 443):
        status, response_time, status_code = checker.get_web_status()
    else:
        status, response_time = checker.get_port_status()
        status_code = None

    location_info = get_or_create_location_info(host)

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


def check_all_services() -> None:
    """Checks the status of all services in the database."""
    with app.app_context():
        try:
            services = Service.query.with_entities(
                Service.service_name, Service.service_url, Service.id, Service.user_id
            ).all()

            for service in services:
                check_and_log_service_status(service)

            db.session.commit()
            logger.info(f"Проверка состояния {len(services)} сервисов завершена.")

            # After checking, we start monitoring changes and cleaning.
            monitor_status_changes()
            cleanup_old_records()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка при проверке сервисов: {e}")


def cleanup_old_records() -> None:
    """Deletes old service status records."""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=RETENTION_PERIOD)
        deleted_count = db.session.query(ServiceStatus).filter(
            ServiceStatus.timestamp < cutoff_date
        ).delete(synchronize_session=False)
        db.session.commit()
        logger.info(f"Удалено {deleted_count} записей старше {RETENTION_PERIOD} дней")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Ошибка при удалении старых записей: {e}")


def monitor_status_changes() -> None:
    """Monitors service status changes and sends notifications."""
    with app.app_context():
        try:
            services = Service.query.with_entities(
                Service.service_name, Service.service_url, Service.id, Service.user_id
            ).all()

            for service in services:
                service_name, service_url, service_id, user_id = service
                user = User.query.get(user_id)
                if not user or not user.email:
                    continue

                current_status = ServiceStatus.query.filter_by(service_url=service_url).order_by(
                    ServiceStatus.timestamp.desc()
                ).first()

                if not current_status:
                    continue

                last_status = ServiceStatus.query.filter_by(service_url=service_url).order_by(
                    ServiceStatus.timestamp.desc()
                ).offset(1).first()

                if last_status and last_status.status != current_status.status:
                    if current_status.status == 'offline':
                        subject = f"Сервис {service_name} недоступен"
                        message = f"Сервис {service_url} перешел в статус 'offline' в {current_status.timestamp}."
                    else:
                        subject = f"Сервис {service_name} снова доступен"
                        message = f"Сервис {service_url} снова в статусе 'online' в {current_status.timestamp}."

                    send_email_notification(subject, message, user.email)
        except Exception as e:
            logger.error(f"Ошибка при мониторинге изменений статуса: {e}")


def calculate_user_sla_data() -> Tuple[Dict[str, int], Dict[str, int], Dict[str, float], Dict[str, float]]:
    """Calculates SLA data for the current user."""
    subquery = (ServiceStatus.query
                .with_entities(
        ServiceStatus.service_url,
        func.max(ServiceStatus.timestamp).label('max_timestamp')
    )
                .group_by(ServiceStatus.service_url)
                .filter_by(user_id=current_user.id)
                ).subquery()

    latest_statuses = ServiceStatus.query.filter_by(user_id=current_user.id).join(
        subquery,
        (ServiceStatus.service_url == subquery.c.service_url) &
        (ServiceStatus.timestamp == subquery.c.max_timestamp)
    ).all()

    all_statuses = ServiceStatus.query.filter_by(user_id=current_user.id).all()

    # Status counting
    total_responses_per_service = {}
    online_count_per_service = {}
    for status in all_statuses:
        url = status.service_url
        total_responses_per_service[url] = total_responses_per_service.get(url, 0) + 1
        if status.status == 'online':
            online_count_per_service[url] = online_count_per_service.get(url, 0) + 1

    # SLA calculation
    sla_results = {}
    for url in total_responses_per_service:
        total = total_responses_per_service[url]
        online = online_count_per_service.get(url, 0)
        sla_results[url] = round((online / total) * 100, 2) if total > 0 else 0

    # Calculation of average response time
    avg_response_times = {}
    for status in all_statuses:
        url = status.service_url
        if status.response_time is not None and status.response_time < DEFAULT_ERROR_RESPONSE_TIME:
            if url not in avg_response_times:
                avg_response_times[url] = {'sum': 0, 'count': 0}
            avg_response_times[url]['sum'] += status.response_time
            avg_response_times[url]['count'] += 1

    final_avg_times = {
        url: data['sum'] / data['count']
        for url, data in avg_response_times.items()
        if data['count'] > 0
    }

    # Total online/offline calculation
    online_count = sum(1 for s in latest_statuses if s.status == "online")
    offline_count = sum(1 for s in latest_statuses if s.status == "offline")

    return (
        total_responses_per_service,
        online_count_per_service,
        sla_results,
        final_avg_times,
        online_count,
        offline_count
    )


# ROUTES
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Имя пользователя уже занято.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/change_settings', methods=['GET', 'POST'])
@login_required
def change_settings():
    pass_form = ChangePasswordForm()
    email_form = ChangeEmailForm()

    if request.method == 'POST':
        if request.form.get('form_type') == 'password':
            if pass_form.validate_on_submit():
                user = User.query.get(current_user.id)
                if user:
                    user.set_password(pass_form.new_password.data)
                    db.session.commit()
                    flash('Пароль успешно изменен.', 'success')
                else:
                    flash('Пользователь не найден.', 'danger')
            else:
                flash('Ошибка валидации формы пароля.', 'danger')

        elif request.form.get('form_type') == 'email':
            if email_form.validate_on_submit():
                user = User.query.get(current_user.id)
                if user:
                    user.email = email_form.email.data
                    db.session.commit()
                    flash('Email успешно изменен.', 'success')
                else:
                    flash('Пользователь не найден.', 'danger')
            else:
                flash('Ошибка валидации формы email.', 'danger')

        return redirect(url_for('change_settings'))

    return render_template(
        'change_settings.html',
        pass_form=pass_form,
        email_form=email_form,
        schedule_interval=SCHEDULE_INTERVAL
    )


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
            flash('Неверное имя пользователя или пароль.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/', methods=['GET'])
@login_required
def index():
    (
        total_responses,
        online_counts,
        sla_results,
        avg_response_times,
        online_count,
        offline_count
    ) = calculate_user_sla_data()

    # We get the latest statuses for display
    subquery = (ServiceStatus.query
                .with_entities(
        ServiceStatus.service_url,
        func.max(ServiceStatus.timestamp).label('max_timestamp')
    )
                .group_by(ServiceStatus.service_url)
                .filter_by(user_id=current_user.id)
                ).subquery()

    latest_services = ServiceStatus.query.filter_by(user_id=current_user.id).join(
        subquery,
        (ServiceStatus.service_url == subquery.c.service_url) &
        (ServiceStatus.timestamp == subquery.c.max_timestamp)
    ).all()

    return render_template(
        'index.html',
        services=latest_services,
        total_responses_per_service=total_responses,
        online_count_per_service=online_counts,
        sla_results=sla_results,
        average_response_time_per_service=avg_response_times,
        online_count=online_count,
        offline_count=offline_count
    )


@app.route('/service_management', methods=['GET'])
@login_required
def service_management():
    services_user = Service.query.filter_by(user_id=current_user.id).with_entities(
        Service.id, Service.service_name, Service.service_url, Service.description
    ).all()
    return render_template('service_management.html', services_user=services_user)


@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    form = AddServiceForm()
    existing_services_count = Service.query.filter_by(user_id=current_user.id).count()

    if existing_services_count >= 10:
        flash('Достигнут лимит сервисов (10).', 'error')
        return redirect(url_for('service_management'))

    if form.validate_on_submit():
        service = Service(
            service_name=form.service_name.data,
            service_url=form.service_url.data,
            description=form.description.data,
            user_id=current_user.id
        )
        db.session.add(service)
        db.session.commit()
        # Check immediately after adding
        check_and_log_service_status((
            service.service_name, service.service_url, service.id, current_user.id
        ))
        db.session.commit()

        flash('Сервис успешно добавлен!', 'success')
        return redirect(url_for('service_management'))

    return render_template('add_service.html', title='Add Service', form=form)


@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id: int):
    service = Service.query.get_or_404(service_id)
    if service.user_id != current_user.id:
        abort(403)

    form = EditServiceForm(obj=service)
    if form.validate_on_submit():
        service.service_name = form.service_name.data
        service.service_url = form.service_url.data
        service.description = form.description.data
        db.session.commit()
        flash('Изменения сохранены!', 'success')
        return redirect(url_for('service_management'))
    return render_template('edit_service.html', title='Edit Service', form=form)


@app.route('/delete_service/<int:service_id>', methods=['POST'])
@login_required
def delete_service(service_id: int):
    service = Service.query.get_or_404(service_id)
    if service.user_id != current_user.id:
        abort(403)

    ServiceStatus.query.filter_by(service_id=service_id).delete(synchronize_session=False)
    db.session.delete(service)
    db.session.commit()
    flash('Сервис удален!', 'success')
    return redirect(url_for('service_management'))


@app.route('/check_services', methods=['GET'])
@login_required
def check_user_services_route():
    """Checks the status of the current user's services and returns JSON."""
    with app.app_context():
        try:
            services = Service.query.filter_by(user_id=current_user.id).with_entities(
                Service.service_name, Service.service_url, Service.id
            ).all()

            results = []
            for service in services:
                service_name, service_url, service_id = service
                host, port = parse_service_url(service_url)
                checker = CheckServer(host, port)

                if port in (80, 443):
                    status, response_time, status_code = checker.get_web_status()
                else:
                    status, response_time = checker.get_port_status()
                    status_code = None
                print(host)
                location_info = get_or_create_location_info(host)

                result = {
                    "service_name": service_name,
                    "service_url": service_url,
                    "status": status,
                    "response_time": f"{response_time:.2f} ms",
                    "service_location": f"{location_info.get('countryCode', 'N/A')} {location_info.get('region', 'N/A')} {location_info.get('city', 'N/A')}",
                    "service_isp": location_info.get('isp', 'N/A'),
                    "service_timezone": location_info.get('timezone', 'N/A'),
                    "status_code": status_code
                }
                results.append(result)

                # Сохраняем статус в БД
                service_status = ServiceStatus(
                    service_name=service_name,
                    service_url=service_url,
                    service_ip=location_info.get('query', 'N/A'),
                    service_location=result["service_location"],
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
            return jsonify(results)
        except Exception as e:
            logger.error(f"Ошибка при проверке сервисов пользователя: {e}")
            return jsonify({"error": "Internal server error"}), 500


@app.route('/sla', methods=['GET'])
@login_required
def sla():
    """Returns SLA statistics for all services."""
    try:
        services = ServiceStatus.query.all()
        total_responses = len(services)
        online_count = sum(1 for s in services if s.status == 'online')

        sla_result = (online_count / total_responses * 100) if total_responses > 0 else 0

        valid_response_times = [s.response_time for s in services if
                                s.response_time is not None and s.response_time < DEFAULT_ERROR_RESPONSE_TIME]
        avg_response_time = sum(valid_response_times) / len(valid_response_times) if valid_response_times else None

        return jsonify({
            "total_responses": total_responses,
            "online_count": online_count,
            "sla": f"{sla_result:.2f}%",
            "average_response_time": f"{avg_response_time:.2f} ms" if avg_response_time is not None else None
        })
    except Exception as e:
        logger.error(f"Ошибка при получении SLA: {e}")
        return jsonify({"error": "Internal server error"}), 500


# SCHEDULER
scheduler = BackgroundScheduler()
scheduler.start()
scheduler.add_job(
    func=check_all_services,
    trigger=IntervalTrigger(seconds=SCHEDULE_INTERVAL),
    id='check_services_job',
    name='Check all services status',
    replace_existing=True
)

# Application termination handler
import atexit

atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')