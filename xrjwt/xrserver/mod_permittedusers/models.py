# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response


class PermittedUsers(Base):
    __tablename__ = 'permitted_users'
    user_email = db.Column(db.String(255), index=True, nullable=False)
    session_id = db.Column(db.String(64), index=True, nullable=False, primary_key=True)
    media_id = db.Column(db.String(64), index=True, nullable=False, primary_key=True)
    content_id = db.Column(db.String(64), index=True, nullable=False, primary_key=True)
