from flask import Flask, jsonify, render_template
import requests
import socket
import time
from database import init_db, ServiceStatus, db
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///services.db'
init_db(app)

SERVICES = [
    'https://example.com',
    'service:port'] # Your services here


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
        if '://' not in service_url and ':' in service_url:
            start_time = time.time()
            host, port = service_url.split(':')
            port = int(port)
            status = 'online' if check_port(host, port) else 'offline'
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
        else:
            try:
                start_time = time.time()
                response = requests.get(service_url, timeout=5)
                end_time = time.time()
                response_time = (end_time - start_time) * 1000
                status = 'online'
            except requests.RequestException as e:
                response_time = None
                status = 'offline'

        service_status = ServiceStatus(
            service_url=service_url,
            status=status,
            response_time=response_time
        )
        db.session.add(service_status)
        results.append({
            "service_url": service_url,
            "status": status,
            "response_time": f"{response_time:.2f} ms" if response_time is not None else None
        })
    print(f"{time.strftime("%H:%M:%S")} - Трыньк!Сервисы успешно проверены!")
    db.session.commit()

    return results


@app.route('/', methods=['GET'])
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
def check_services_route():
    with app.app_context():
        return jsonify(check_services())

scheduler = BackgroundScheduler()
scheduler.add_job(func=check_services_route, trigger='interval', seconds=300) # Set the interval in seconds to request updated data
scheduler.start()

@app.route('/sla', methods=['GET'])
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