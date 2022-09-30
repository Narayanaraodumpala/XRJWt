# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from ..models import Base

# Define a User model/Database
class Contact(Base):
    __tablename__ = 'contact_user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(64), nullable=True)
    last_name = db.Column(db.String(64), nullable=True)
    name=db.Column(db.String(64),nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    message = db.Column(db.String(255), nullable=True)
    is_demo = db.Column(db.Boolean, unique=False, default=True)
    demo_date = db.Column(db.DateTime, nullable=True)
    subject = db.Column(db.String(150), nullable=True)
    xr_updates = db.Column(db.Boolean, unique=False, default=False)