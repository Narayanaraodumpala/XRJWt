# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response

class SessionMedia(Base):

    __tablename__ = 'session_media'

    session_id = db.Column(db.String(64), index = True, nullable = False, primary_key = True)
    media_id = db.Column(db.String(64), index=True, primary_key = True)
    media_type = db.Column(db.String(64))
    media_path = db.Column(db.String(255))