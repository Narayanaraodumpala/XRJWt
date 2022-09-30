# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import time
from ..models import Base
from flask import jsonify, make_response
        
class Companyinfo(Base):

    __tablename__ = 'compinfo'
    
    logo =  db.Column(db.String(255))
    company_id = db.Column(db.String(64), index = True, nullable = False, primary_key = True)
    company_name = db.Column(db.String(255)) # will store more information based on content type
    ceo_name =  db.Column(db.String(128))
    email =  db.Column(db.String(255))
    number =  db.Column(db.String(15))
    website = db.Column(db.String(100))
    address = db.Column(db.String(255)) 
    status =  db.Column(db.String(25))
    technology = db.Column(db.String(255))
    language = db.Column(db.String(255))
    timezone = db.Column(db.String(255))
    company_created_by = db.Column(db.String(255))
    no_of_license=db.Column(db.String(255))
    license_key= db.Column(db.String(255))