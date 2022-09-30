# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response
        
class Session(Base):

    __tablename__ = 'sessions'

    session_id = db.Column(db.String(64), index = True, nullable = False, primary_key = True)
    event_name= db.Column(db.String(64), index=True, nullable = False, primary_key = True)
    event_type = db.Column(db.String(64))
    parent_event_name = db.Column(db.String(64))
    session_status  = db.Column(db.String(32), index=True)
    access_type = db.Column(db.String(32), index=True) #public or private
    max_users = db.Column(db.Integer)
    host_user_email = db.Column(db.String(128))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    description = db.Column(db.String(255))
    environment_id = db.Column(db.String(64))
    category = db.Column(db.String(64))
    # security_key = db.Column(db.String(255))
    
    # avatar_config = db.Column(db.String(255))
    content = db.Column(db.String(255))
    
    # def __repr__(self):
        # responseObject = {
                # 'status': 'success',
                # 'data': {
                # 'sessionID' : self.session_id,
                # 'tagName' : self.tag_name,
                # }
            # }
        # return responseObject
