from email import message
import secrets

from flasgger import swag_from
from sqlalchemy import desc
import sqlalchemy
from .models import Contact
from xrserver import db
from .schemas import ContactSchema
import functools

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
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, Response
from flask_sqlalchemy import SQLAlchemy
from ..mailsetup import email_send, mail_template
from datetime import datetime, timedelta, date

# auth = HTTPBasicAuth(scheme="Bearer")
mod_contact = Blueprint("contact", __name__, url_prefix="/contact")

# Add Contact Form
@mod_contact.route("/addContact", methods=("GET", "POST"))
def addContact():
    if request.method == "POST":
        try:
            name =  request.form["name"]
            email = request.form["email"]
            subject = request.form['subject']
            message = request.form["message"]
           
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )
      
        error = None
       
        if (
            email is None
            or name is None
            or subject is None 
            or message is None
        ):
            error = "Please enter all required fields."
        if error is None:
            new_contact = Contact(
                email=email,
                name=name,
                message=message,
                subject= subject,
                is_demo=False,
            )
            db.session.add(new_contact)
            db.session.commit()

            print("success")
            email_send(email, 13, name)
            mail_template(2, email, name,"", message,"","",subject)
            return make_response(
                jsonify(
                    {
                        "status": "success",
                        "message": "Thank You for Contacting us.",
                        "data": "",
                    }
                )
            )

        else:
            flash(error)
            return make_response(
                jsonify({"status": "fail", "message": error, "data": ""})
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )


# Add Contact Form
@mod_contact.route("/bookDemo", methods=("GET", "POST"))
def bookDemo():
    if request.method == "POST":
        try:
            email = request.form["email"]
            firstname = request.form["firstName"]
            lastname = request.form["lastName"]
            phonenumber = request.form["phoneNumber"]
            message = request.form["message"]
            # demo_date = request.form["demo_date"]
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )
      
        error = None
       
        if (
            email is None
            or firstname is None
            or lastname is None
            or phonenumber is None
            or message is None
            # or demo_date is None
        ):
            error = "Please enter all required fields."
        # check if user already exists
        # if Contact.query.filter_by(email=email).first() is not None:
        #     error = "User {} is already registered.".format(email)

        # insert the user
        if error is None:
            new_contact = Contact(
                email=email,
                last_name=lastname,
                first_name=firstname,
                phone_number=phonenumber,
                message=message,
                # demo_date=datetime.strptime(demo_date,'%d-%m-%Y %H:%M:%S'),
            )
            db.session.add(new_contact)
            db.session.commit()
            print(new_contact)
            print("success")
            email_send(email, 13, firstname)
            
            data = user_data(email)
            mail_template(3, email, firstname, lastname, message, phonenumber)
            # print(user_data(email))
            return make_response(
                jsonify(
                    {
                        "status": "success",
                        "message": "Thanks for Contacting us",
                        "data": "",
                    }
                )
            )

        else:
            flash(error)
            return make_response(
                jsonify({"status": "fail", "message": error, "data": ""})
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )
    
def user_data(email):
    results = db.session.query(
        Contact.email,
        Contact.first_name,
        Contact.last_name,
        Contact.phone_number,
        Contact.message,
    ).filter_by(email=email).order_by(sqlalchemy.desc(Contact.date_created)).all()
    first_Contact = results[0]
    if first_Contact is None:
            error = "No existing user"
            return error
    else:
        contact_schema = ContactSchema()
        data = contact_schema.dump(first_Contact)
        return data
    
    
    
############################################################################

# get Contact Data
@mod_contact.route("/getContact", methods=("GET", "POST", "DELETE"))
def user():
    if request.method == "POST":
        try:
            email = request.form["email"]
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )

        contact = (
            db.session.query(
                Contact.first_name,
                Contact.last_name,
                Contact.phone_number,
                Contact.demo_date,
                Contact.message,
                Contact.is_demo,
                Contact.email,
            )
            .filter_by(email=email)
            .first()
        )

        if contact is None:
            error = "No existing user"
            responseObject = {"status": "fail", "data": "", "message": error}
            return make_response(jsonify(responseObject))

        else:
            contact_schema = ContactSchema()
            data = contact_schema.dump(contact)
            responseObject = {"status": "success", "data": data, "message": ""}
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""}))

# View Contact table list
@mod_contact.route('/getContactList', methods=['GET'])
@swag_from('../docs/contact/getcontact_comanylist.yaml')
def getContactList():
    if request.method == 'GET':
        # user = Contact.query.order_by(desc(Contact.date_created)).all()
        contact = db.session.query(
                                Contact.id,
                                Contact.first_name,
                               Contact.last_name,
                                Contact.email,
                                Contact.phone_number,
                                Contact.is_demo,
                                ).all()
        if contact is not None:
            contact_schema = ContactSchema()
            data = contact_schema.dump(contact, many=True)
            respData = {'user': data}
            responseObject = {
                'status': 'success',
                'data': respData,
                'message': ''
            }
            # username, company_name, email, role, gender
        return make_response(jsonify(responseObject))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202

# Get Users list based on company name and if empty it will display all users

# delete Contact
@mod_contact.route('/deleteUser', methods=('GET', 'POST', 'PUT'))
def deleteUsers():
    if request.method == 'POST':
        try:
            email = request.form["email"]
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )
        user = Contact.query.filter_by(email=email).first()

        if user is None:
            error = "No existing user"
            responseObject = {"status": "fail", "data": "", "message": error}
            return make_response(jsonify(responseObject))

        else:
            db.session.delete(user)
            db.session.commit()
            responseObject = {"status": "success", "data": email,
                              "message": f"User {email} deleted Successfully!"}
        return make_response(jsonify(responseObject))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202

    