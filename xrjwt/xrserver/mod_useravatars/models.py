from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response
        
class UserAvatars(Base):

    __tablename__ = 'user_avatars'

    user_id = db.Column(db.String(125), index = True, nullable = False, primary_key = True)
    model_file_path = db.Column(db.String(255), index = True, nullable = False)
    #avatar_id = db.Column(db.String(64),index = True, nullable = False)