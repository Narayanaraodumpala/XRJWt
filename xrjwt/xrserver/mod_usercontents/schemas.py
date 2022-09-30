from xrserver import ma
from .models import UserContents
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class UserContentsSchema(SQLAlchemySchema):
    class Meta:
        model = UserContents
       
    content_id = auto_field()
    content_name = auto_field()
    content_type = auto_field()
    content_load_type = auto_field() 
    thumbnail_path = auto_field()
    description = auto_field()
    owner = auto_field()
    access_type = auto_field()
    path = auto_field()
    version = auto_field()
    file_name = auto_field()
    build_target = auto_field()
    uploaded_by = auto_field()
