from xrserver import ma
from .models import Media
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class MediaSchema(SQLAlchemySchema):
    class Meta:
        model = Media

    media_id = auto_field()
    media_type = auto_field()
    thumbnail_path = auto_field()
    description = auto_field()
    owner = auto_field()
    uploaded_by = auto_field()
    access_type = auto_field()
    permitted_users = auto_field()
    path = auto_field()
    version = auto_field()
    file_name = auto_field()