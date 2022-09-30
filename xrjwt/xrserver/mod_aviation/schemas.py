# ---------    By Narayanarao Dumpala --------------#

# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.

from .models import Aviation
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

# create a Schema for auto-config the models

class AviationSchema(SQLAlchemySchema):
    class Meta:
        model = Aviation

    id = auto_field()
    session_id = auto_field()
    event_id = auto_field()
    device_id = auto_field()
    start_time = auto_field()
    end_time = auto_field()
    ip_address = auto_field()
    mode = auto_field()
    user_id = auto_field()
    timestampTime = auto_field()

    module = auto_field()
    user_name = auto_field()
    idle_time = auto_field()
    teleportation = auto_field()
    component = auto_field()
    action = auto_field()
    modeEndTime = auto_field()
    idleStartTime = auto_field()
    modeStartTime = auto_field()
    idlEndTime = auto_field()
    teleportStartPos = auto_field()
    teleportEndPos = auto_field()
    operation = auto_field()
    operationStartTime = auto_field()
    operationStartDate=auto_field()
    operationEndTime = auto_field()
    operationEnddate=auto_field()
    start_date=auto_field()
    end_date=auto_field()
    modeEndDate=auto_field()
    idleStartDate=auto_field()
    modeStartDate=auto_field()
    idlEndDate=auto_field()
    timestampDate=auto_field()

