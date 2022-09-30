# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import SessionUsers
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class SessionUsersSchema(SQLAlchemySchema):
    class Meta:
        model = SessionUsers
       
    session_id = auto_field()
    user_id = auto_field()
    user_role = auto_field()
    user_avatar = auto_field()
    is_favourite = auto_field()