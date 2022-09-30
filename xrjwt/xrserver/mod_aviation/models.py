
# ---------    By Narayanarao Dumpala --------------#



# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response

# create a model for save the data to Mysql database with respective Fields
class Aviation(Base):
    __tablename__ = 'aviation'
    id = db.Column(db.Integer, index=True, primary_key=True)
    session_id = db.Column(db.String(64), index=True)
    event_id = db.Column(db.String(64), nullable=False)
    device_id = db.Column(db.String(64), nullable=True)
    user_id = db.Column(db.String(64))
    user_name = db.Column(db.String(64))
    idle_time = db.Column(db.String(64), nullable=True)
    teleportation = db.Column(db.String(64), nullable=True)
    start_date = db.Column(db.String(64))
    start_time = db.Column(db.String(64))
    end_time = db.Column(db.String(64), nullable=True)
    end_date = db.Column(db.String(64), nullable=True)
    ip_address = db.Column(db.String(64), nullable=True)
    mode = db.Column(db.String(64), nullable=True)
    timestampTime = db.Column(db.String(64), nullable=True)
    timestampDate = db.Column(db.String(64), nullable=True)
    module = db.Column(db.String(64), nullable=True)
    component = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(64), nullable=True)
    modeEndTime = db.Column(db.String(64), nullable=True)
    modeEndDate = db.Column(db.String(64), nullable=True)
    idleStartTime = db.Column(db.String(64), nullable=True)
    idleStartDate = db.Column(db.String(64), nullable=True)
    modeStartTime = db.Column(db.String(64), nullable=True)
    modeStartDate = db.Column(db.String(64), nullable=True)
    idlEndTime = db.Column(db.String(64), nullable=True)
    idlEndDate = db.Column(db.String(64), nullable=True)
    teleportStartPos = db.Column(db.String(64), nullable=True)
    teleportEndPos = db.Column(db.String(64), nullable=True)
    operation = db.Column(db.String(64), nullable=True)
    operationStartTime = db.Column(db.String(64), nullable=True)
    operationStartDate = db.Column(db.String(64), nullable=True)
    operationEndTime = db.Column(db.String(64), nullable=True)
    operationEnddate = db.Column(db.String(64), nullable=True)

