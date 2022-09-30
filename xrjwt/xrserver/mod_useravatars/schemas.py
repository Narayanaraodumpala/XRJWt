from xrserver import ma
from .models import UserAvatars
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class UserAavatarsSchema(SQLAlchemySchema):
    class Meta:
        model = UserAvatars
     
    user_id = auto_field()
    model_file_path = auto_field()
    #avatar_id = auto_field()