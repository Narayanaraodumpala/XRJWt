# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response
        
class SessionUsers(Base):

    __tablename__ = 'sessions_users'

    session_id = db.Column(db.String(64), index = True, nullable = False, primary_key = True)
    user_id = db.Column(db.String(255), index = True, nullable = False, primary_key = True)
    user_role = db.Column(db.String(64))
    user_avatar = db.Column(db.String(255))
    eventid = db.Column(db.String(255),nullable = True)
    
    is_favourite = db.Column(db.Integer)
    