from xrserver import ma
from .models import Companyinfo
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field

class CompanyinfoSchema(SQLAlchemySchema):
    class Meta:
        model = Companyinfo
       
    logo = auto_field()
    company_id = auto_field()
    company_name = auto_field()
    ceo_name = auto_field()
    email = auto_field()
    number = auto_field()
    website = auto_field()
    address = auto_field()
    status = auto_field()
    technology = auto_field()
    language = auto_field()
    timezone = auto_field()
    company_created_by = auto_field()
    no_of_license=auto_field()
    license_key= auto_field()