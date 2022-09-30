# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import Event
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field


class EventSchema(SQLAlchemySchema):
    class Meta:
        model = Event

    session_id = auto_field()
    event_name = auto_field()
    event_type = auto_field()
    parent_event_name = auto_field()
    session_status = auto_field()
    access_type = auto_field()
    max_users = auto_field()
    host_user_email = auto_field()
    start_date = auto_field()
    end_date = auto_field()
    description = auto_field()
    environment_id = auto_field()
    application_id = auto_field()
    tools_id = auto_field()
    category = auto_field()