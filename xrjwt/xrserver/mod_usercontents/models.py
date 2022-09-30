from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response
        
class UserContents(Base):

    __tablename__ = 'user_contents'
    
    content_id = db.Column(db.String(64), index = True, nullable = False, primary_key = True)
    content_name = db.Column(db.String(64))
    content_type = db.Column(db.String(64), index=True)
    content_load_type = db.Column(db.String(64), index=True)
    thumbnail_path =  db.Column(db.String(128),nullable = True)
    description = db.Column(db.String(128)) 
    owner =  db.Column(db.String(128))
    access_type = db.Column(db.String(32))
    path =  db.Column(db.String(255))
    version = db.Column(db.String(32))
    file_name = db.Column(db.String(128),primary_key = True,nullable = False)
    build_target = db.Column(db.String(32),primary_key = True,nullable = False)
    uploaded_by = db.Column(db.String(255))
