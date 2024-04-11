# models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime

# Import db from __init__.py
from app import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    scans = db.relationship('Scan', backref='users', lazy=True)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False) 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Flask-Login required methods
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

# class Scan(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     hostname = db.Column(db.String(255), nullable=False)
#     ip_address = db.Column(db.String(45), nullable=False)
#     timestamp = db.Column(db.DateTime, nullable=False)
#     cve_data = db.Column(db.JSON)  # Store CVE data as JSON


# class Scan(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     hostname = db.Column(db.String(255), nullable=False)
#     ip_address = db.Column(db.String(45), nullable=False)
#     timestamp = db.Column(db.DateTime, nullable=False)
#     cves = db.relationship('CVE', backref='scan', lazy=True)

# class CVE(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
#     cve_id = db.Column(db.String(50), nullable=False)
#     description = db.Column(db.Text, nullable=False)
#     vulnerability_score = db.Column(db.Float)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    cves = db.relationship('CVE', backref='scan', lazy=True)

class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    cve_id = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    vulnerability_score = db.Column(db.Float)