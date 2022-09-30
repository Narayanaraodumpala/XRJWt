# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import contentAccess
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field


class contentAccessSchema(SQLAlchemySchema):
    class Meta:
        model = contentAccess

    invitee_email = auto_field()
    content_id = auto_field()
    # invite_link = auto_field()
