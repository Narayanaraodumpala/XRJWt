# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import ma
from .models import User
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class UserSchema(SQLAlchemySchema):
    class Meta:
        model = User
    email = auto_field()
    password_hash = auto_field()
    first_name= auto_field()
    last_name = auto_field()
    gender = auto_field()
    role = auto_field()
    date_of_birth = auto_field()
    phone_number = auto_field()
    user_name = auto_field()
    token = auto_field()
    is_active = auto_field()
    vrcode = auto_field()
    company_name = auto_field()
    system_ID = auto_field()
    login_status = auto_field()
    is_social_user = auto_field()
    provider = auto_field()
    image_path = auto_field()
 
