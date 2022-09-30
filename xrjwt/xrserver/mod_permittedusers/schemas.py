# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import PermittedUsers
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class PermittedUsersSchema(SQLAlchemySchema):
    class Meta:
        model = PermittedUsers
        
    user_email = auto_field()
    session_id = auto_field()
    media_id = auto_field()
    content_id = auto_field()