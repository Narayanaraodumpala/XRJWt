# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import Contact
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class ContactSchema(SQLAlchemySchema):
    class Meta:
        model = Contact
        
    id = auto_field()
    email = auto_field()
    first_name= auto_field()
    last_name = auto_field()
    name=auto_field()
    phone_number = auto_field()
    message = auto_field()
    demo_date = auto_field()
    is_demo = auto_field()
    subject = auto_field()
    xr_updates = auto_field()