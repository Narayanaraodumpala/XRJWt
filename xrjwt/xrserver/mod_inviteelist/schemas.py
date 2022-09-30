# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import InviteeList
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field


class InvieeListSchema(SQLAlchemySchema):
    class Meta:
        model = InviteeList

    invitee_email = auto_field()
    session_id = auto_field()
    invite_link = auto_field()
