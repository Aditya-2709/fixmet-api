from flask import Flask, redirect, request, jsonify, render_template, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
# from flask_oauth import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import pandas as pd
import os
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@host:port/dbname')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key_here')
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "https://fixmet.netlify.app"}})

# oauth = OAuth(app)
# google = oauth.remote_app(
#     'google',
#     consumer_key='49113625938-l3utqnkjfqia1fq6u2033rvsjmhgujjn.apps.googleusercontent.com',  # From Google Cloud Console
#     consumer_secret='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',
#     request_token_params={'scope': 'email profile'},
#     base_url='https://www.googleapis.com/oauth2/v1/',
#     request_token_url=None,
#     access_token_method='POST',
#     access_token_url='https://accounts.google.com/o/oauth2/token',
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
# )

# Email configuration
EMAIL_ADDRESS = "your_email@example.com"
EMAIL_PASSWORD = "your_email_password"

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)  # Added name field
    password_hash = db.Column(db.String(128))
    appointments = db.relationship('Appointment', backref='user', lazy=True)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # hospital, bank, office
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    appointments = db.relationship('Appointment', backref='service', lazy=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    appointment_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='confirmed')

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        # Add token verification logic here
        return f(*args, **kwargs)
    return decorated

# Email sending function
def send_confirmation_email(user_email, service_name, appointment_time):
    msg = MIMEText(f'Your appointment with {service_name} is confirmed for {appointment_time}')
    msg['Subject'] = 'Appointment Confirmation - Fixmet'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = user_email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp_server.sendmail(EMAIL_ADDRESS, user_email, msg.as_string())

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://127.0.0.1:5500"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = generate_password_hash(data['password'])
    new_user = User(email=data['email'], name=data['name'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login successful', 'user_id': user.id, 'name': user.name, 'token': access_token})

def handler(event, context):
    from wsgi import wsgi_handler
    return wsgi_handler(app, event, context)

@app.route('/api/service/register', methods=['POST'])
def service_register():
    data = request.get_json()
    if Service.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Service already exists'}), 400
    
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_service = Service(
        name=data['name'],
        type=data['type'],
        email=data['email'],
        password_hash=hashed_password
    )
    db.session.add(new_service)
    db.session.commit()
    return jsonify({'message': 'Service registered successfully'})

@app.route('/api/service/login', methods=['POST'])
def service_login():
    data = request.get_json()
    service = Service.query.filter_by(email=data['email']).first()
    if not service or not check_password_hash(service.password_hash, data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    return jsonify({'message': 'Login successful', 'service_id': service.id})

@app.route('/api/book_appointment', methods=['POST'])
@token_required
def book_appointment():
    data = request.get_json()
    service_id = data['service_id']
    user_id = data['user_id']
    
    # Find next available slot
    last_appointment = Appointment.query.filter_by(service_id=service_id)\
        .order_by(Appointment.appointment_time.desc()).first()
    
    if last_appointment:
        next_slot = last_appointment.appointment_time + timedelta(minutes=30)
    else:
        next_slot = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)
    
    # Create appointment
    appointment = Appointment(
        user_id=user_id,
        service_id=service_id,
        appointment_time=next_slot
    )
    db.session.add(appointment)
    db.session.commit()

    # Send confirmation email
    user = User.query.get(user_id)
    service = Service.query.get(service_id)
    send_confirmation_email(user.email, service.name, next_slot)

    return jsonify({
        'message': 'Appointment booked successfully',
        'appointment_time': next_slot.isoformat()
    })

@app.route('/api/user/appointments/<int:user_id>', methods=['GET'])
@token_required
def get_user_appointments(user_id):
    appointments = Appointment.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': appt.id,
        'service': Service.query.get(appt.service_id).name,
        'time': appt.appointment_time.isoformat(),
        'status': appt.status
    } for appt in appointments])

@app.route('/api/service/appointments/<int:service_id>', methods=['GET'])
@token_required
def get_service_appointments(service_id):
    appointments = Appointment.query.filter_by(service_id=service_id).all()
    data = [{
        'user_email': User.query.get(appt.user_id).email,
        'time': appt.appointment_time.isoformat(),
        'status': appt.status
    } for appt in appointments]
    
    return jsonify(data)

@app.route('/api/service/export/<int:service_id>', methods=['GET'])
@token_required
def export_service_appointments(service_id):
    appointments = Appointment.query.filter_by(service_id=service_id).all()
    data = [{
        'User Email': User.query.get(appt.user_id).email,
        'Time': appt.appointment_time.isoformat(),
        'Status': appt.status
    } for appt in appointments]
    
    df = pd.DataFrame(data)
    filename = f"service_{service_id}_appointments.xlsx"
    df.to_excel(filename, index=False)
    return send_file(filename, as_attachment=True)

# @app.route('/api/login/google')
# def google_login():
#     return google.authorize(callback='http://localhost:5000/api/login/google/authorized')

# @app.route('/api/login/google/authorized')
# def google_authorized():
#     resp = google.authorized_response()
#     if resp is None or resp.get('access_token') is None:
#         return jsonify({'message': 'Access denied'}), 401
#     access_token = resp['access_token']
#     user_info = google.get('userinfo', token=(access_token,))
#     email = user_info.data['email']
#     name = user_info.data['name']

#     user = User.query.filter_by(email=email).first()
#     if not user:
#         # Auto-signup for new Google users
#         new_user = User(email=email, name=name, password_hash=None)
#         db.session.add(new_user)
#         db.session.commit()
#         user = new_user

#     token = create_access_token(identity=user.id)
#     # Redirect back to frontend with user data in query params
#     return redirect(f'http://localhost:3000/?token={token}&user_id={user.id}&email={email}&name={name}')

# @google.tokengetter
# def get_google_oauth_token():
#     return None

# Create database
with app.app_context():
    db.create_all()
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
