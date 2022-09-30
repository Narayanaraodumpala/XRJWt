# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import Oculus
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class OculusSchema(SQLAlchemySchema):
    class Meta:
        model = Oculus
        
    id = auto_field()
    oculus_id = auto_field()