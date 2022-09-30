import functools
#from datetime import time
from flasgger import swag_from
from flask import jsonify, make_response, send_from_directory, send_file
from flask import stream_with_context, Response

import base64
from base64 import b64encode
from json import dumps
import io
import os
#import psutil
from werkzeug.utils import secure_filename

# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from xrserver import db,app

# Import module models
from .models import Companyinfo
from .schemas import  CompanyinfoSchema
mod_compinfo = Blueprint('compinfo', __name__, url_prefix='/compinfo')
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# adding new Company
@mod_compinfo.route('/addCompany', methods=("GET", "POST"))
@jwt_required()
def addCompany():
    if request.method == 'POST':
        try :
            idenetity=get_jwt_identity()
            companyid  = request.form['companyid']
            companyname = request.form['company_name']
            ceo_name = request.form['ceo_name']
            email = request.form['email']
            number = request.form['number']
            website = request.form['website']
            address = request.form['address']
            status = request.form['status']
            # technology = request.form['technology']
            created_by = request.form['created_by']
            no_of_license=request.form['no_of_license']
            license_key=request.form['license_key']
    
        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form Data'}))
            
        error = None

        if not companyid:
            error = 'Missing "Company ID"'
        elif not companyname:
            error = 'Missing "company_name"'
        elif not ceo_name:
            error = 'Missing "ceo_name"'
        elif not email:
            error = 'Missing "Email"'
        elif not number:
            error = 'Missing "Number"'
        elif not website:
            error = 'Missing "Website"'
        elif not address:
            error = 'Missing "Address"'
        elif not status:
            error = 'Missing "Status"'
        elif not license_key :
                error = 'Missing "license_key"'
        elif not no_of_license:
            error = 'Missing "no_of_license"'
        # elif not technology:
        #     error = 'Missing "Technology"'
        elif not created_by:
            error = 'Missing "Company Created By"'

        elif Companyinfo.query.filter_by(company_id=companyid,company_name = companyname).first() is not None :
            error = 'Duplicate session'

        if error is None:
            cinfo = Companyinfo()
            cinfo.company_id = companyid
            cinfo.company_name = companyname
            cinfo.ceo_name = ceo_name
            cinfo.email = email
            cinfo.number = number
            cinfo.website = website
            cinfo.address = address
            cinfo.status = status
            cinfo.technology = 'IT'
            cinfo.language = 'EN'
            cinfo.license_key =license_key
            cinfo.no_of_license = no_of_license
            cinfo.company_created_by = created_by

            db.session.add(cinfo)
            db.session.commit()
            print('Success')
            responseObject = {
                    'status': 'success',
                    'message': 'New Company Name added sucessfully',
                    'data' : ''
                }
            return make_response(jsonify(responseObject)), 202
        
        else:
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : ''
            }    
        
            return make_response(jsonify(responseObject)), 401
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


# get company details based on company ID
@mod_compinfo.route("/getCompanyDetails",methods=("GET", "POST") )
@jwt_required()
def getCompanyDetails():
    if request.method == "POST":
        idenetity=get_jwt_identity()
        try:
            companyid = request.form["companyid"]
        
        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form Data'}))

        compData = (
            db.session.query(
                Companyinfo.date_created,
                Companyinfo.company_id,
                Companyinfo.company_name,
                Companyinfo.ceo_name,
                Companyinfo.email,
                Companyinfo.number,
                Companyinfo.website,
                Companyinfo.address,
                Companyinfo.status,
                Companyinfo.technology,
                Companyinfo.company_created_by
            ).filter_by(company_id=companyid).first())

        if compData is None:
            error = "No existing company Data"
            responseObject = {"status": "fail", "data": "", "message": error}
            return make_response(jsonify(responseObject))

        else:
            comp_schema = CompanyinfoSchema()
            data = comp_schema.dump(compData)
            responseObject = {"status": "success", "data": data, "message": ""}
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""}))

# View list of companies
@mod_compinfo.route('/getCompanyList', methods=['GET'])
@jwt_required()
def getCompanyList():
    if request.method == 'GET':
        idenetity=get_jwt_identity()
        # user = User.query.order_by(desc(User.date_created)).all()
        compData = db.session.query(Companyinfo.date_created,
                Companyinfo.company_id,
                Companyinfo.company_name,
                Companyinfo.ceo_name,
                Companyinfo.email,
                Companyinfo.number,
                Companyinfo.website,
                Companyinfo.address,
                Companyinfo.status,
                Companyinfo.technology,
                Companyinfo.company_created_by).all()
        if compData is not None:
            comp_schema = CompanyinfoSchema()
            data = comp_schema.dump(compData,many = True)
            respData = {'compData' : data}
            responseObject = {
                'status': 'success',
                'data': respData,
                'message' : ''
            }
            # username, company_name, email, role, gender
        return make_response(jsonify(responseObject))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''})), 202

# Get companies list based on companyid and if empty it will display all companies data
@mod_compinfo.route('/getCompanyBasedList', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getCompanyBasedList():
    if request.method == 'POST':
        idenetity=get_jwt_identity()
        try :
            companyid = request.form['companyid']
        
        except Exception as e : 
            return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : 'missing Company Name'}))

        if not companyid:
            # error = "No Company Name Entered"
            compData = db.session.query(Companyinfo.date_created,
                Companyinfo.company_id,
                Companyinfo.company_name,
                Companyinfo.ceo_name,
                Companyinfo.email,
                Companyinfo.number,
                Companyinfo.website,
                Companyinfo.address,
                Companyinfo.status,
                Companyinfo.technology,
                Companyinfo.company_created_by).all()
            comp_schema = CompanyinfoSchema()
            data = comp_schema.dump(compData,many = True)
            responseObject = {
                'status': 'success',
                'data': data,
                'message' : ''
            } 
            return make_response(jsonify(responseObject)), 202
        else:
            # error = "Company name Entered"
            compData = db.session.query(Companyinfo.date_created,
                Companyinfo.company_id,
                Companyinfo.company_name,
                Companyinfo.ceo_name,
                Companyinfo.email,
                Companyinfo.number,
                Companyinfo.website,
                Companyinfo.address,
                Companyinfo.status,
                Companyinfo.technology,
                Companyinfo.company_created_by).filter_by(company_id=companyid).all()
            comp_schema = CompanyinfoSchema()
            data = comp_schema.dump(compData,many = True)
            responseObject = {
                'status': 'success',
                'data': data,
                'message' : ''
            } 
            
            return make_response(jsonify(responseObject)), 202    
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

# deleting a company
@mod_compinfo.route('/deleteCompany', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def deleteCompany():
    if request.method == 'POST':
        idenetity=get_jwt_identity()
        try:
            companyid = request.form["companyid"]
        
        except Exception as e : 
            return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : 'missing Company Name'}))

        compData = Companyinfo.query.filter_by(company_id=companyid).first()

        if compData is None:
            error = "No existing compData"
            responseObject = {"status": "fail", "data": "", "message": error}
            return make_response(jsonify(responseObject))

        else:
            db.session.delete(compData)
            db.session.commit()
            responseObject = {"status": "success", "data": companyid, "message": "Company deleted successfully"}
        return make_response(jsonify(responseObject))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202


# Update company infomation
@mod_compinfo.route("/updateCompany", methods=["PUT"])
@jwt_required()
def updateCompany():
    if request.method == "PUT":
        try:
            idenetity=get_jwt_identity()
            company_id  = request.form['companyid']
            companyName = request.form['company_name']
            ceo_name = request.form['ceo_name']
            email = request.form['email']
            number = request.form['number']
            website = request.form['website']
            address = request.form['address']
            status = request.form['status']
            # technology = request.form['technology']

        except Exception as e:
            return make_response(jsonify({"status": "fail", "message": str(e), "data": "Data is missing"}))
            
        compData = Companyinfo.query.filter_by(company_id=company_id).first()

        if not ceo_name:
            ceo_name = compData.ceo_name
        else:
            ceo_name = ceo_name

        if not companyName:
            company_name = compData.company_name
        else:
            company_name = companyName

        if not email:
            email = compData.email
        else:
            email = email
        
        if not number:
            number = compData.number
        else:
            number = number

        if not website:
            website = compData.website
        else:
            website = website

        if not address:
            address = compData.address
        else:
            address = address
        
        if not status:
            status = compData.status
        else:
            status = status

        if compData.company_id is None:
            return "Data is missing"
        else:
            compData.company_name = company_name
            compData.ceo_name = ceo_name
            compData.email = email
            compData.number = number
            compData.website = website
            compData.address = address
            compData.status = status

            db.session.commit()

            responseObject = {
                "status": "success",
                "data": "",
                "message": "Company details updated successfully!"
            }
        return make_response(jsonify(responseObject))
    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )
