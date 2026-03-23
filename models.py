from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.orm import validates
import re
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()

# -------------------- USER MODEL --------------------
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

    # -------------------- EMAIL VALIDATION --------------------
    @validates('email')
    def validate_email(self, key, email):
        regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        if not re.match(regex, email):
            raise ValueError("Invalid email address")
        return email

    # -------------------- SERIALIZATION --------------------
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
# -------------------- LOGIN HISTORY --------------------
class LoginHistory(db.Model):
    __tablename__ = 'login_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<LoginHistory User {self.user_id} @ {self.login_time}>"