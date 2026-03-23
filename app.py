from flask import Flask, request, jsonify, session
from flask_restful import Api, Resource
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from flask_cors import CORS
from datetime import datetime, timedelta
import pytz
import os
import requests
import base64
import logging
import re
from sqlalchemy.orm import validates

app = Flask(__name__)
api = Api(app)

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///edams.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['SESSION_COOKIE_HTTPONLY'] = True

logging.basicConfig(level=logging.INFO)


from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()
login_manager = LoginManager()
jwt = JWTManager()


db.init_app(app)
bcrypt.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)
jwt.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='user')
    is_approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    login_history = db.relationship(
        'LoginHistory',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan'
    )

    payments = db.relationship(
        'Payment',
        backref='user',
        lazy=True,
        cascade='all, delete-orphan'
    )


    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    @validates('email')
    def validate_email(self, key, email):
        regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        if not re.match(regex, email):
            raise ValueError("Invalid email address")
        return email

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_approved": self.is_approved,
            "created_at": self.created_at.isoformat()
        }

    def __repr__(self):
        return f"<User {self.id}: {self.username}>"

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True)

class Payment(db.Model):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    phone_number = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(100), nullable=True)
    result_code = db.Column(db.Integer, nullable=True)
    result_desc = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklist

CONSUMER_KEY = os.getenv("CONSUMER_KEY")
CONSUMER_SECRET = os.getenv("CONSUMER_SECRET")
SHORTCODE = os.getenv("SHORTCODE")
PASSKEY = os.getenv("LIPA_NA_MPESA_ONLINE_PASSKEY")
CALLBACK_URL = os.getenv("CALLBACK_URL")

def format_phone(phone):
    phone = phone.strip().replace("+", "")
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    return phone

def get_access_token():
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    credentials = f"{CONSUMER_KEY}:{CONSUMER_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {"Authorization": f"Basic {encoded_credentials}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["access_token"]

def generate_password():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    raw_password = f"{SHORTCODE}{PASSKEY}{timestamp}"
    encoded_password = base64.b64encode(raw_password.encode()).decode()
    return encoded_password, timestamp

class Register(Resource):
    def post(self):
        data = request.get_json()
        if User.query.filter_by(email=data.get('email')).first():
            return {"message": "Email already exists"}, 400

        user = User(
            username=data.get("username"),
            email=data.get("email"),
            role=data.get("role", "user")
        )
        user.set_password(data.get("password"))
        db.session.add(user)
        db.session.commit()
        token = create_access_token(identity=str(user.id))
        return {"user": user.to_dict(), "access_token": token}, 201

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        if not user or not user.check_password(data.get('password')):
            return {"message": "Invalid credentials"}, 401

        token = create_access_token(identity=str(user.id))
        session['user_id'] = user.id
        login_entry = LoginHistory(user_id=user.id)
        db.session.add(login_entry)
        db.session.commit()
        return {"user": user.to_dict(), "access_token": token}, 200

class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        blacklist.add(jti)
        user_id = get_jwt_identity()
        last_login = LoginHistory.query.filter_by(user_id=user_id).order_by(LoginHistory.login_time.desc()).first()
        if last_login:
            last_login.logout_time = datetime.utcnow()
            db.session.commit()
        session.pop('user_id', None)
        return {"message": "Logged out"}, 200

class VerifyToken(Resource):
    @jwt_required()
    def get(self):
        user = User.query.get(get_jwt_identity())
        if not user:
            return {"message": "Invalid token"}, 401
        return {"user": user.to_dict()}, 200

class LoginHistoryResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        history = LoginHistory.query.filter_by(user_id=user_id).order_by(LoginHistory.login_time.desc()).all()
        kenya_tz = pytz.timezone("Africa/Nairobi")
        data = []
        for entry in history:
            login_time = entry.login_time.replace(tzinfo=pytz.UTC).astimezone(kenya_tz)
            logout_time = entry.logout_time.replace(tzinfo=pytz.UTC).astimezone(kenya_tz) if entry.logout_time else None
            data.append({
                "login_time": login_time.strftime("%Y-%m-%d %H:%M:%S"),
                "logout_time": logout_time.strftime("%Y-%m-%d %H:%M:%S") if logout_time else None
            })
        return jsonify(data)

class STKPushResource(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        amount = data.get("amount")
        phone = data.get("phone_number")
        if not amount or not phone:
            return {"error": "Amount and phone number required"}, 400

        phone = format_phone(phone)
        user_id = get_jwt_identity()

        try:
            access_token = get_access_token()
            password, timestamp = generate_password()
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            payload = {
                "BusinessShortCode": SHORTCODE,
                "Password": password,
                "Timestamp": timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": amount,
                "PartyA": phone,
                "PartyB": SHORTCODE,
                "PhoneNumber": phone,
                "CallBackURL": CALLBACK_URL,
                "AccountReference": "EDAMS",
                "TransactionDesc": "Subscription Payment"
            }
            response = requests.post(
                "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
                json=payload,
                headers=headers,
                timeout=30
            )
            response_data = response.json()
            logging.info(response_data)

            payment = Payment(user_id=user_id, phone_number=phone, amount=amount,
                              transaction_id=response_data.get("CheckoutRequestID"))
            db.session.add(payment)
            db.session.commit()
            return response_data, response.status_code
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error: {http_err.response.text}")
            return {"error": http_err.response.text}, http_err.response.status_code
        except Exception as e:
            logging.error(str(e))
            return {"error": "Failed to initiate payment"}, 500

@app.route("/callback", methods=["POST"])
def mpesa_callback():
    data = request.get_json()
    logging.info(data)
    callback = data.get("Body", {}).get("stkCallback", {})
    result_code = callback.get("ResultCode")
    checkout_request_id = callback.get("CheckoutRequestID")
    payment = Payment.query.filter_by(transaction_id=checkout_request_id).first()

    if payment:
        payment.result_code = result_code
        payment.result_desc = callback.get("ResultDesc")
        if int(result_code) == 0:
            metadata = callback.get("CallbackMetadata", {}).get("Item", [])
            payment_data = {item["Name"]: item.get("Value") for item in metadata}
            db.session.commit()
            return jsonify({"message": "Payment successful", "data": payment_data}), 200
        db.session.commit()
        return jsonify({"message": "Payment failed", "ResultCode": result_code}), 400
    return jsonify({"error": "Payment not found"}), 404

api.add_resource(Register, '/auth/register')
api.add_resource(Login, '/auth/login')
api.add_resource(Logout, '/auth/logout')
api.add_resource(VerifyToken, '/auth/verify')
api.add_resource(LoginHistoryResource, '/auth/history')
api.add_resource(STKPushResource, '/payment/stkpush')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)