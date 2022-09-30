# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response
        
class Media(Base):

    __tablename__ = 'media'
    
    media_id = db.Column(db.String(64), index = True, nullable = False, primary_key = True)
    media_type = db.Column(db.String(64), index=True)
    thumbnail_path =  db.Column(db.String(255),nullable = True)
    description = db.Column(db.String(255)) # will store more information based on content type
    owner =  db.Column(db.String(128))
    uploaded_by =  db.Column(db.String(128))
    access_type = db.Column(db.String(32))
    permitted_users = db.Column(db.String(255)) 
    path =  db.Column(db.String(255))
    version = db.Column(db.String(32))
    file_name = db.Column(db.String(255))

    
