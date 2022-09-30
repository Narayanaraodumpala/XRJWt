from email import message
import secrets
from sqlalchemy import desc
from .models import Oculus
from xrserver import db
from .schemas import OculusSchema
import functools
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# from datetime import time
from flask import jsonify, make_response
from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import time 
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, Response
from flask_sqlalchemy import SQLAlchemy
from ..mailsetup import email_send
from datetime import datetime, timedelta, date

# auth = HTTPBasicAuth(scheme="Bearer")
mod_oculus = Blueprint("oculus", __name__, url_prefix="/oculus")

# Add Contact Form
@mod_oculus.route("/addOculus", methods=("GET", "POST"))
@jwt_required()
def oculus():
    if request.method == "POST":
        identity=get_jwt_identity()
        startime=time.time()
        try:
            oculus_id =  request.form["oculus_id"]
           
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )
      
        error = None
       
        if (
            oculus_id is None
        ):
            error = "Please enter all required fields."
        if error is None:
            new_oculus = Oculus(
                oculus_id=oculus_id,
            )
            db.session.add(new_oculus)
            db.session.commit()

            print("success")
            email_send(oculus_id, 12)
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            endtime=time.time()
            return make_response(
                jsonify(
                    {
                        "status": "success",
                        "message": "Thank You for registering with us.",
                        "data": "",
                        # 'access':access,
                        # 'refresh':refresh
                        'Time taken':endtime - startime
                    }
                )
            )

        else:
            flash(error)
            endtime:time.time()
            return make_response(
                jsonify({"status": "fail", "message": error, "data": "",'Time taken':endtime - startime})
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )

############# below codes are for future use  #############
# get Contact Data
# @mod_oculus.route("/getContact", methods=("GET", "POST", "DELETE"))
# def user():
#     if request.method == "POST":
#         try:
#             email = request.form["email"]
#         except Exception as e:
#             return make_response(
#                 jsonify({"status": "fail", "message": str(e), "data": ""})
#             )

#         contact = (
#             db.session.query(
#                 Contact.first_name,
#                 Contact.last_name,
#                 Contact.phone_number,
#                 Contact.demo_date,
#                 Contact.message,
#                 Contact.is_demo,
#                 Contact.email,
#             )
#             .filter_by(email=email)
#             .first()
#         )

#         if contact is None:
#             error = "No existing user"
#             responseObject = {"status": "fail", "data": "", "message": error}
#             return make_response(jsonify(responseObject))

#         else:
#             contact_schema = ContactSchema()
#             data = contact_schema.dump(contact)
#             responseObject = {"status": "success", "data": data, "message": ""}
#         return make_response(jsonify(responseObject))

#     return make_response(
#         jsonify({"status": "fail", "message": "check method type.", "data": ""}))

# # View Contact table list
# @mod_oculus.route('/getContactList', methods=('GET', 'POST', 'PUT'))
# def getContactList():
#     if request.method == 'GET':
#         # user = Contact.query.order_by(desc(Contact.date_created)).all()
#         contact = db.session.query(
#                                 Contact.id,
#                                 Contact.first_name,
#                                Contact.last_name,
#                                 Contact.email,
#                                 Contact.phone_number,
#                                 Contact.is_demo,
#                                 ).all()
#         if contact is not None:
#             contact_schema = ContactSchema()
#             data = contact_schema.dump(contact, many=True)
#             respData = {'user': data}
#             responseObject = {
#                 'status': 'success',
#                 'data': respData,
#                 'message': ''
#             }
#             # username, company_name, email, role, gender
#         return make_response(jsonify(responseObject))

#     return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202

# # Get Users list based on company name and if empty it will display all users

# # delete Contact
# @mod_oculus.route('/deleteUser', methods=('GET', 'POST', 'PUT'))
# def deleteUsers():
#     if request.method == 'POST':
#         try:
#             email = request.form["email"]
#         except Exception as e:
#             return make_response(
#                 jsonify({"status": "fail", "message": str(e), "data": ""})
#             )
#         user = User.query.filter_by(email=email).first()

#         if user is None:
#             error = "No existing user"
#             responseObject = {"status": "fail", "data": "", "message": error}
#             return make_response(jsonify(responseObject))

#         else:
#             db.session.delete(user)
#             db.session.commit()
#             responseObject = {"status": "success", "data": email,
#                               "message": f"User {email} deleted Successfully!"}
#         return make_response(jsonify(responseObject))

#     return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202



# # Add Contact Form
# @mod_oculus.route("/bookDemo", methods=("GET", "POST"))
# def bookDemo():
#     if request.method == "POST":
#         try:
#             email = request.form["email"]
#             firstname = request.form["firstName"]
#             lastname = request.form["lastName"]
#             phonenumber = request.form["phoneNumber"]
#             message = request.form["message"]
#             demo_date = request.form["demo_date"]
#         except Exception as e:
#             return make_response(
#                 jsonify({"status": "fail", "message": str(e), "data": ""})
#             )
      
#         error = None
       
#         if (
#             email is None
#             or firstname is None
#             or lastname is None
#             or phonenumber is None
#             or message is None
#             or demo_date is None
#         ):
#             error = "Please enter all required fields."
#         # check if user already exists
#         # if Contact.query.filter_by(email=email).first() is not None:
#         #     error = "User {} is already registered.".format(email)

#         # insert the user
#         if error is None:
#             new_contact = Contact(
#                 email=email,
#                 last_name=lastname,
#                 first_name=firstname,
#                 phone_number=phonenumber,
#                 message=message,
#                 demo_date=datetime.strptime(demo_date,'%d-%m-%Y %H:%M:%S'),
#             )
#             db.session.add(new_contact)
#             db.session.commit()

#             print("success")
#             email_send(email, 11, firstname)
#             return make_response(
#                 jsonify(
#                     {
#                         "status": "success",
#                         "message": "Thanks for Contacting us",
#                         "data": "",
#                     }
#                 )
#             )

#         else:
#             flash(error)
#             return make_response(
#                 jsonify({"status": "fail", "message": error, "data": ""})
#             )

#     return make_response(
#         jsonify({"status": "fail", "message": "Check method type.", "data": ""})
#     )