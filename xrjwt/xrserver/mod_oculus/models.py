# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from ..models import Base

# Define a User model/Database
class Oculus(Base):
    __tablename__ = 'oculus_id'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    oculus_id = db.Column(db.String(128), nullable=False)