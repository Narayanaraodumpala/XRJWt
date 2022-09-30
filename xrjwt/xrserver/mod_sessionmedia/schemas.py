# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import SessionMedia
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class SessionMediaSchema(SQLAlchemySchema):
    class Meta:
        model = SessionMedia
        
    session_id = auto_field()
    media_id = auto_field()
    media_type = auto_field()
    media_path = auto_field()