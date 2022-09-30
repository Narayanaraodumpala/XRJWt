from dbm import ndbm
import secrets
from tokenize import Token
from venv import create

from flasgger import swag_from
from sqlalchemy import  desc

from xrserver.mod_companyinfo.models import Companyinfo
from .models import User
from xrserver import db
from .schemas import UserSchema
import functools
import jwt
import urllib.parse
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
key="secret"
app=Flask(__name__, instance_relative_config=True)
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# from datetime import time
import time
from flask import jsonify, make_response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
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
'''
code for jwt , code by narayanarao dumpala



from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import set_refresh_cookies
from flask_jwt_extended import unset_jwt_cookies


from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


'''

# Akhil...........................
from flask import Flask, Response
from flask_sqlalchemy import SQLAlchemy
import random

# ................................
########### Siddharth ###########
from ..mailsetup import email_send
import datetime
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
s = URLSafeTimedSerializer("secretCode!")
# vrcode generator
# Getting systemRandom class instance out of secrets module
# app = Flask(__name__, instance_relative_config=True)





def vrotp():
    secretsGenerator = secrets.SystemRandom()
    vrcode = secretsGenerator.randrange(100000, 999999)
    return vrcode


########### Siddharth ###########
auth = HTTPBasicAuth(scheme="Bearer")
mod_auth = Blueprint("auth", __name__, url_prefix="/auth")
mod_user = Blueprint("user", __name__)


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
   
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


########### Siddharth ###########

# Token Confirmation
@mod_auth.route("/confirm_email/<token>")
def confirm_email(token):
    try:
        if token is not None:
            email = s.loads(token, salt="email-confirm", max_age=3600)
            update_user = User.query.filter_by(email=email).first()
            update_user.is_active = True
            update_user.token = ""
            db.session.commit()
            return redirect("https://demo.xrconnect.io/#/login", code=302)
    except SignatureExpired as e:
        flash("The confirmation link is invalid or has expired.", "danger")
        return "<h1>The token is expired!</h1>"
        # return make_response(jsonify({"status": "fail", "message": str(e), "data": ""}))
    return "<h1>The token works!</h1>"

# password reset verify


@mod_auth.route("/reset_Password_verify/<token>")
def reset_Password_verify(token):
    try:
        if token is not None:
            email = s.loads(token, salt="email-confirm", max_age=600)
            update_user = User.query.filter_by(email=email).first()
            update_user.is_active = True
            db.session.commit()
            return redirect('https://demo.xrconnect.io/#/updatePassword', code=302)
            # return make_response(jsonify({
            #             "status": "success",
            #             "message": "Account is activated.",
            #             "data": "",
            #         }
            #     )
            # )
    except SignatureExpired as e:
        flash("The confirmation link is invalid or has expired.", "danger")
        return "<h1>The token is expired!</h1>"
        # return make_response(jsonify({"status": "fail", "message": str(e), "data": ""}))
    return "<h1>The token works!</h1>"

########### Siddharth ###########

# User Registration


@mod_auth.route("/register", methods=("GET", "POST"))

def register():
    # get the post data
    if request.method == "POST":
        start_time = time.time()
        print(start_time)
        try:
            email = request.form["email"]
            password = request.form["password"]
            # firstname = request.form["FirstName"]
            # lastname = request.form["LastName"]
            gender = request.form["Gender"]
            role = request.form["Role"]
            company_name = request.form['companyName']
            # phonenumber = request.form["PhoneNumber"]
            #date_of_birth = request.form["dob"]
            username = request.form["UserName"]
            token = s.dumps(email, salt="email-confirm")
            is_active = False
            g.user = user
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )

        error = None

        if (
            email is None
            or password is None
            or username is None
            # or firstname is None
            # or lastname is None
            or gender is None
            # or role is None
            # or dob is None
        ):
            error = "Please enter all required fields."
        # check if user already exists
        if User.query.filter_by(email=email).first() is not None:
            error = "User {} is already registered.".format(email)

        # insert the user
        if error is None:
            new_user = User(
                email=email,
                password_hash=  bcrypt.generate_password_hash(password).decode('utf-8'),
                # last_name=lastname,
                # first_name=firstname,
                gender=gender,
                role=role,
                company_name=company_name,
                #date_of_birth = dob,
                token=token,
                is_active=is_active,
                user_name=username,
                # phone_number=phonenumber,
            )
            db.session.add(new_user)
            db.session.commit()

            print("success")
            email_send(email, 1, '' ,token)
            end_time = time.time()
            duration = end_time - start_time
            print("duration", duration)
            print(f'Time taken to run: {time.time() - start_time} seconds')
            return make_response(
                jsonify(
                    {
                        "status": "success",
                        "message": "Registered successfully, Please check your email to activate the account.",
                        "data": "",
                        'token':token,
                        "Time taken": duration
                        # "token": token,
                    }
                )
            )

        else:
            # flash(error)
            # print(error)

            return make_response(
                jsonify({"status": "fail", "message": error, "data": ""})
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )

# User Registration by Admin

@mod_auth.route("/addUser", methods=("GET", "POST"))
@jwt_required()
def addUser():
        start_time=time.time()
        identity=get_jwt_identity()
        if identity['role']=='SuperAdmin':
            try:
                firstname = request.form["FirstName"]
                lastname = request.form["LastName"]
                gender = request.form["Gender"]
                role = request.form["Role"]
                company_name = request.form['companyName']
                email = request.form["email"]
                phonenumber = request.form["PhoneNumber"]
                username = request.form["UserName"]
                password = 'Password@123'
                token = s.dumps(email, salt="email-confirm")
                is_active = False
                # g.user = user
                print('==========')
                
            except Exception as e:
                return make_response(
                    jsonify({"status": "fail", "message": str(e), "data": ""})
                )

            error = None

            if (
                email is None
                or username is None
                or gender is None
                or role is None
                or company_name is None
            ):
                error = "Please enter all required fields."
                print('++++++++')
            
            # check if user already exists
            if User.query.filter_by(email=email).first() is not None:
                error = "User {} is already registered.".format(email)
                

            # insert the user
            #jtoken=jwt.encode({'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},key=key)
            '''
            code for jwt , code by narayanarao dumpala
            access_token = create_access_token(identity=user.email)
            refresh_token = create_refresh_token(identity=user.email)
            '''
            user = User.query.filter_by(email=email).first()
        
            if error is None:
                new_user = User(
                    email=email,
                    password_hash=generate_password_hash(
                        password, method="sha256"),
                    last_name=lastname,
                    first_name=firstname,
                    gender=gender,
                    role=role,
                    company_name=company_name,
                    token=token,
                    is_active=is_active,
                    user_name=username,
                    phone_number=phonenumber,
                )
                db.session.add(new_user)
                db.session.commit()

                print("success")
                email_send(email, 7, '',token)
                end_time = time.time()
                duration = end_time - start_time
                
                
                print("duration", duration)
                print(f'Time taken to run: {time.time() - start_time} seconds')
                return make_response(
                    jsonify(
                        {
                        
                            "status": "success",
                            "message": "Registered successfully.",
                            "data": "",
                            "Time taken": duration,
                            
                            #"access_token":access_token,
                            #"refresh_token":refresh_token
                    } ,
                    )
                )

            else:
                flash(error)
                return make_response(
                    jsonify({"status": "fail", "message": error, "data": ""})
                )
        else:
                return make_response(
                        jsonify({"status": "fail", "message": "you don't have permissions", "data": ""})
                    )
            

        return make_response(
         jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )


# User login
@mod_auth.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        start_time = time.time()
        try:
            email = request.form["email"]
            password = request.form["password"]

        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )

        error = None
        # pw_hash="$2y$10$uf9kzIkxMRnh/y1NcAtCSuXJGd1WphWHTXD34h9k5iISAqw45r3/u"

        if not email:
            error = 'Missing "email"'
        elif not password:
            error = 'Missing "password"'
        else:
            user = User.query.filter_by(email=email).first()
            if user is None:
                error = "Entered email doesn't exist. Please register"
            elif not bcrypt.check_password_hash(user.password_hash,password):#
                error = "Login failed. Incorrect password."

        if error is None:
            user = User.query.filter_by(email=email).first()
            if user.is_active is False and user.token != "":
                error = "The given email address has not been activated. To activate your account, you must first confirm the email address."
                return make_response(
                    jsonify({"status": "fail", "message": error, "data": ""})
                )
            else:
                #calling get_sas_token function to creat&response sas token
                privatesastoken=get_private_sas_token()
                publicsastoken=get_public_sas_token()
                compData=db.session.query(Companyinfo.company_id, Companyinfo.company_name, Companyinfo.license_key, Companyinfo.no_of_license,Companyinfo).join(User,(User.company_name==Companyinfo.company_id)).filter(User.email ==email).first()
                if  compData is not None:
                    userData = {
                        "email": email,
                        # "first_name": user.first_name,  
                        # "last_name": user.last_name,
                        "user_name": user.user_name,
                        "gender": user.gender,
                        "role": user.role,                                                           
                        "system_id": user.system_ID,
                        "login_status": user.login_status,
                        "public_sas_token":privatesastoken,
                        "privatesastoken":publicsastoken
                    
                    }
                    end_time = time.time()
                    duration = end_time - start_time
                    print("duration", duration)
                    print(f'Time taken to run: {time.time() - start_time} seconds')
                    
                    # access_token = create_access_token(identity=user.email)
                    # refresh_token = create_refresh_token(identity=user.email)
                    refresh = create_refresh_token(identity=userData)
                    access = create_access_token(identity=userData)
                    resp =  make_response(jsonify(
                            {
                                "status": "success",
                                "data": {
                                    "token": user.is_active,
                                    "user_data": userData,
                                    "access_token":access,
                                    "refresh_token":refresh,
                                    "company_id":compData.company_id,
                                    "company_name":compData.company_name,"license_key":compData.license_key,"no_of_license" : compData.no_of_license
                                },
                                "message": "",
                                "Time taken": duration
                            }
                        )
                    )
                    
                    # set_access_cookies(resp, access_token)
                    # set_refresh_cookies(resp,refresh_token)
                    return resp
                else:
                    userData = {
                        "email": email,
                        # "first_name": user.first_name,  
                        # "last_name": user.last_name,
                        "user_name": user.user_name,
                        "gender": user.gender,
                        "role": user.role,                                                           
                        "system_id": user.system_ID,
                        "login_status": user.login_status,
                        "public_sas_token":privatesastoken,
                        "privatesastoken":publicsastoken,
                        "company_id":' ',
                                    "company_name":user.company_name,"license_key":'',"no_of_license" : ''
                       
                    
                    }
                    end_time = time.time()
                    duration = end_time - start_time
                    print("duration", duration)
                    print(f'Time taken to run: {time.time() - start_time} seconds')
                    
                    # access_token = create_access_token(identity=user.email)
                    # refresh_token = create_refresh_token(identity=user.email)
                    refresh = create_refresh_token(identity=userData)
                    access = create_access_token(identity=userData)
                    resp =  make_response(jsonify(
                            {
                                "status": "success",
                                "data": {
                                    "token": user.is_active,
                                    "user_data": userData,
                                    "access_token":access,
                                    "refresh_token":refresh,
                                    
                                },
                                "message": "",
                                "Time taken": duration
                            }
                        )
                    )
                    
                    # set_access_cookies(resp, access_token)
                    # set_refresh_cookies(resp,refresh_token)
                    return resp
                    
                

        else:
            return make_response(
                jsonify({"status": "fail", "message": error, "data": ""})
            )
    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )
    

# xr-device login
@mod_auth.route("/device_login", methods=("GET", "POST"))
def device_login():
    if request.method == "POST":
        start_time=time.time()
        try:
            email = request.form['email']
            password = request.form["password"]
            system_ID = request.form["system_id"]

        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": "Not working!"})
            )

        error = None
        print('email=',email)
        print('password=',password)
        print('systemid=',system_ID)
        compData=db.session.query(Companyinfo.company_id, Companyinfo.company_name, Companyinfo.license_key, Companyinfo.no_of_license,Companyinfo).join(User,(User.company_name==Companyinfo.company_id)).filter(User.email ==email).first()
        if compData is not None:
            
        
            company_data={
                 "company_id":compData.company_id,
                                    "company_name":compData.company_name,"license_key":compData.license_key,"no_of_license" : compData.no_of_license
            }
        else:
            user = User.query.filter_by(email=email).first()
            company_data={
                  "company_id":' ',
                                    "company_name":user.company_name,"license_key":'',"no_of_license" : ''
              }
        if not system_ID:
            error = 'Missing "systemID"'
            
        if not system_ID:
            login_status = False
        else:
            login_status = True

        if not email:
            error = 'Missing "email"'
        elif not password:
            error = 'Missing "password"'
        else:
            user = User.query.filter_by(email=email).first()
            privatesastoken= get_private_sas_token()
            pubilcsastoken=get_public_sas_token()
            # refresh = create_refresh_token(identity=user.email)
            # access = create_access_token(identity=user.email)
            if user is None:
                error = "Incorrect email."
            elif not bcrypt.check_password_hash(user.password_hash,password):
                error = "Incorrect password."

        if error is None:
            #user = User.query.filter_by(email=email).first()
            if user.is_active is False:
                error = "Account is not verified."
                return make_response(jsonify({"status": "fail", "message": error, "data": ""}))
            # elif user.system_ID is not None and user.login_status is True:
            #     error = "Account is already active, Please logout from previous device and try again!!"
            #     return make_response(jsonify({"status": "fail", "message": error, "data": ""}))
            elif user.system_ID is None and user.login_status is False:
                error = "Account is already active, Please logout from previous device and try again!!"
                return make_response(jsonify({"status": "fail", "message": error, "data": ""}))
            elif user.system_ID is not None and user.login_status is True and user.system_ID != system_ID:
                status_status(email, login_status, system_ID)
                if compData is not None:
                  userData = {
                    "email": email,
                    "user_name": user.user_name,
                    "gender": user.gender,
                    "role": user.role,
                    "company": user.company_name,
                    "system_id": user.system_ID,
                    "login_status": user.login_status,
                    "public_sas_token":pubilcsastoken,
                    "privatesastoken":privatesastoken,
                    "company_info":company_data
                }
                end_time=time.time()
                duration=end_time - start_time
                refresh = create_refresh_token(identity=userData)
                access = create_access_token(identity=userData)
                resp =  make_response(jsonify(
                        {
                            "status": "success",
                            "data": {
                                "token": user.is_active,
                                "user_data": userData,
                                "access_token":access,
                                "refresh_token":refresh
                            },
                            "message": user.email+" is logged in with new Device ID. "+ user.system_ID,
                            "Time taken": duration
                        }
                    )
                )
                #return make_response(jsonify({"status": "success",
                # "message": user.email+" is logged in with new Device ID. "+ user.system_ID,
                # "data": userData,
                # "Time taken":duration
                # }))
                return resp
            else:
                status_status(email, login_status, system_ID)
                userData = {
                    "email": email,
                    "user_name": user.user_name,
                    "gender": user.gender,
                    "role": user.role,
                    "company": user.company_name,
                    "system_id": user.system_ID,
                    "login_status": user.login_status,
                    "public_sas_token":pubilcsastoken,
                    "privatesastoken":privatesastoken,
                    "company_info":company_data
                }
                end_time=time.time()
                duration=end_time - start_time
                refresh = create_refresh_token(identity=userData)
                access = create_access_token(identity=userData)
                resp =  make_response(jsonify(
                        {
                            "status": "success",
                            "data": {
                                "token": user.is_active,
                                "user_data": userData,
                                "access_token":access,
                                "refresh_token":refresh
                            },
                            "message": "Same device logged in.",
                            "Time taken": duration
                        }
                    )
                )
                # return make_response(
                #     jsonify({
                #         "status": "success",
                #         "data": {"token": user.is_active, "user_data": userData},
                #         "message": "Same device logged in."
                #         }
                #     )
                # )
                return resp
        else:
            return make_response(
                jsonify({"status": "fail", "message": error, "data": ""})
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )

# device status reset


def status_status(email, login_status, system_ID):
    if email is not None:
        update_user = User.query.filter_by(email=email).first()
        update_user.login_status = login_status
        update_user.system_ID = system_ID
        db.session.commit()
        return "Success, device is activated"


# device logout functionality for xr-application
@mod_auth.route("/device_logout", methods=("GET", "POST"))
@jwt_required()
def device_logout():
    if request.method == "POST":
        start_time=time.time()
        identity = get_jwt_identity()
        
        try:
            email = identity['email']
        except Exception as e:
            return make_response(jsonify({"status": "fail", "message": str(e), "data": "Entered Data is missing"}))

        error = None
        if (email is None):
            return "Please enter all required fields."
        # check if user already exists
        if User.query.filter_by(email=email).first() is None:
            return "Please enter correct email address.".format(email)
            
        if not email:
            return 'Enter valid email'
        else:
            update_status = User.query.filter_by(email=email).first()
            update_status.login_status = False
            update_status.system_ID = ""
            db.session.commit()
            message = 'Logged out Successfully.'
            end_time= time.time()
            duration=end_time - start_time
            return make_response(jsonify({"status": "success", "message": message,'Time taken':duration, "data": ""}))
    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )


# get user
@mod_auth.route("/getUser", methods=["POST" ])
@jwt_required()
def user():
    if request.method == "POST":
        start_time=time.time()
        identity = get_jwt_identity()
        try:
            email = identity['email']
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )

        user = (
            db.session.query(
                User.first_name,
                User.last_name,
                User.phone_number,
                User.gender,
                User.role,
                User.user_name,
                User.is_active,
                User.email,
                User.date_of_birth,
                User.company_name,
                User.system_ID,
                User.login_status
            )
            .filter_by(email=email)
            .first()
        )

        if user is None:
            error = "No existing user"
            responseObject = {"status": "fail", "data": "", "message": error}
            return make_response(jsonify(responseObject))

        else:
            # refresh = create_refresh_token(identity=user.email)
            # access = create_access_token(identity=user.email)
            user_schema = UserSchema()
            data = user_schema.dump(user)
            end_time=time.time()
            responseObject = {"status": "success", 
                #               'access':access,
                # 'refresh':refresh,
                'Time taken':end_time-start_time,
                "data": data, "message": ""}
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""}))

# View Users table list with accordingly pagination
@mod_auth.route('/getuserpaginationlist',methods=['GET'])
@jwt_required()
def getuserpagination():
    starttime=time.time()
    identity=get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('size', 5, type=int)
    email = request.args.get('email', '', type=str)
    email = "%{}%".format(email)
    if email is None:
        bookmarks = User.query.paginate(page=page, per_page=per_page,error_out=False)
    else:        
        bookmarks = User.query.filter(User.email.like(email)).paginate(page=page, per_page=per_page,error_out=False)
    
  
    data = []

    for bookmark in bookmarks.items:
        data.append({
            'company_name': bookmark.company_name,
            'user_name': bookmark.user_name,
            'first_name': bookmark.first_name,
            'last_name': bookmark.last_name,
            'gender': bookmark.gender,
            'email': bookmark.email,
            'phone_number': bookmark.phone_number,
            'vrcode': bookmark.vrcode,
            'role': bookmark.role,
            'is_active': bookmark.is_active,
        })
        endtime=time.time()

    """ meta = {
        "page": bookmarks.page,
        'pages': bookmarks.pages,
        'total_count': bookmarks.total,
        'prev_page': bookmarks.prev_num,
        'next_page': bookmarks.next_num,
        'has_next': bookmarks.has_next,
        'has_prev': bookmarks.has_prev,

    } """
    
    return jsonify({'data': data, "totalItems": bookmarks.total,'Time taken':endtime - starttime,"totalPages":bookmarks.pages,"currentPage":bookmarks.page}),202
# View Users table list
@mod_auth.route('/getUsersList', methods=["GET"])
@jwt_required()
def getUsersList():
    if request.method == 'GET':
        starttime=time.time()
        identity = get_jwt_identity()
        print(identity)
        if identity['role'] == 'SuperAdmin':
            # user = User.query.order_by(desc(User.date_created)).all()
            user = db.session.query(User.company_name,
                                    User.user_name,
                                    User.first_name,
                                    User.last_name,
                                    User.gender,
                                    User.email,
                                    User.phone_number,
                                    User.vrcode,
                                    User.role,
                                    User.is_active,
                                    ).all()
            # refresh = create_refresh_token(identity=user)
            # access = create_access_token(identity=user)
            if user is not None:
                user_schema = UserSchema()
                data = user_schema.dump(user, many=True)
                respData = {'user': data}
                endtime=time.time()
                responseObject = {
                    'status': 'success',
                    'data': respData,
                    # 'refresh':refresh,
                    # 'access':access,
                    'message': '',
                    'Time taken':endtime - starttime
                }
                # username, company_name, email, role, gender
            return make_response(jsonify(responseObject))
        else:
            return make_response(jsonify({'status': 'fail', 'message': "you don't have the permission", 'data': ''})), 202        
    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202

# Get Users list based on company name and if empty it will display all users


@mod_auth.route('/getCompanyUsersList', methods=('GET', 'POST', 'PUT'))
def getCompanyUsersList():
    if request.method == 'POST':
        starttime=time.time()
        try:
            company_name = request.form['company_name']
        except Exception as e:
            return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'missing Company Name'}))

        print(company_name)

        if not company_name:
            # error = "No Company Name Entered"
            com = db.session.query(User.user_name,
                                   User.company_name,
                                   User.email,
                                   User.role,
                                   User.gender).all()
            user_schema = UserSchema()
            data = user_schema.dump(com, many=True)
            # refresh = create_refresh_token(identity=user.email)
            # access = create_access_token(identity=user.email)
            endtime=time.time()
            responseObject = {
                'status': 'success',
                'data': data,
                # 'refresh':refresh,
                # 'access':access,
                'message': '',
                'Time taken':starttime - endtime
            }
            return make_response(jsonify(responseObject)), 202 
        else:
            # error = "Company name Entered"
            # refresh = create_refresh_token(identity=user.email)
            # access = create_access_token(identity=user.email)
            endtime=time.time()
            com = db.session.query(User.user_name,
                                   User.company_name,
                                   User.email,
                                   User.role,
                                   User.gender).filter_by(company_name=company_name).all()
            user_schema = UserSchema()
            data = user_schema.dump(com, many=True)
            responseObject = {
                'status': 'success',
                # ,
                'data': data,
                'message': '',
                 'Time taken':starttime - endtime
            }

            return make_response(jsonify(responseObject)), 202
    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))

# reset password
@mod_auth.route("/resetPassword", methods=("GET", "POST", "DELETE"))
def resetPassword():
    if request.method == "POST":
        starttime=time.time()
        try:
            email = request.form["email"]
        except Exception as e:
            return make_response(
                jsonify(
                    {"status": "fail", "message": str(
                        e), "data": "Data is missing"}
                )
            )
        # print(email)
        user = User.query.filter_by(email=email).first()
        # refresh = create_refresh_token(identity=user.email)
        # access = create_access_token(identity=user.email)
        if user is None:
            endtime=time.time()
            print("email not found")
            error = "No existing user"
            responseObject = {"status": "fail", 'Time taken':endtime - starttime,"data": "", "message": error}
            return make_response(jsonify(responseObject))
        else:
            token = s.dumps(email, salt="email-confirm")
            user.is_active = False
            user.token = token
            db.session.commit()
            email_send(email, 7, '', token)
            endtime=time.time()

            responseObject = {
                "status": "success",
                "data": "",
                "message": "Reset Password sent to Mail!",
                "token": token,
                "email": email,
                'Time taken':endtime - starttime,
                # 'access':access,
                # 'refresh':refresh
            }
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )

# update password


@mod_auth.route("/updatePassword", methods=("GET", "POST"))
def updatePassword():
    if request.method == "POST":
        starttime=time.time()
        try:
            uemail = request.form['email']
            upass = request.form['password']
        except Exception as e:
            return make_response(
                jsonify(
                    {"status": "fail", "message": str(
                        e), "data": "Data is missing"}
                )
            )

        user = User.query.filter_by(email=uemail).first()
        # return user.email
        

        if user.email is None and user.token is None:
            return "data is missing"
        
        else:
            password_hash =  bcrypt.generate_password_hash(upass).decode('utf-8')
            user.password_hash = password_hash
            user.token = ''
            user.is_active = True
            db.session.commit()
            email_send(user.email, 9)
            endtime=time.time()
            responseObject = {
                "status": "success",
                "data": "",
                'Time taken':endtime - starttime,
                "message": "Password Reset successful!"
            }
        return make_response(jsonify(responseObject))
    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )


# generate VR code from Web
@mod_auth.route("/generatevrcode", methods=("GET", "POST"))
def generatevrcode():
    starttime=time.time()
    tmp = request.form
    for tmp in request.form:
        print(tmp)
    if request.method == "POST":
        try:
            email = request.form['email']
            print(email)
        except Exception as e:
            return make_response(
                jsonify(
                    {"status": "fail", "message": str(
                        e), "data": "Data is missing"}
                )
            )
        user = User.query.filter_by(email=email).first()
        # return user.email
        print(user)
        
        if user.email is None:
            return "User is missing"
        else:
            user.vrcode = vrotp()
            db.session.commit()
            emdtime=time.time()
            responseObject = {
                "status": "success",
                "data": user.vrcode,
                'Time taken':emdtime - starttime,
                "message": "VR Code Generated successfully!",
                
            }
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )

# User login in VR via OTP


@mod_auth.route("/vrlogin", methods=("GET", "POST"))
def vrlogin():
    # VR OTP login
    if request.method == "POST":
        starttime=time.time()
        try:
            vrcode = request.form["vrcode"]

        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )
        # check if user vrcode exists
        if User.query.filter_by(vrcode=vrcode).first() is None:
            error = "vrcode {} doesn't exist.".format(vrcode)
            endtime=time.time()
            return make_response(
                jsonify(

                    {
                        "status": "fail",
                        "data": "",
                        "message": error,
                        'Time taken ':endtime - starttime
                    }
                )
            )
        else:
            user = User.query.filter_by(vrcode=vrcode).first()
            endtime=time.time()
            userData = {
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "user_name": user.user_name,
                "vr code":user.vrcode,
                'Time taken': endtime - starttime
            }  # , 'is_active' : user.is_active

            user.vrcode = ''
            db.session.commit()
            email_send(user.email, 10)
            endtime=time.time()
            return make_response(
                jsonify(
                    {
                        "status": "success",
                        "data": {"Account Status": user.is_active, "user_data": userData},
                        "message": "VR device connected",
                        'Time taken': endtime - starttime
                    }
                )
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )


# delete usersp=rcwd&sv=2021-04-10&sr=c&sig=c5VAfI3zncyUmNSHA55W0nBOru1pmcrTLbxZRKyBvIY%3D

# from datetime import datetime, timedelta
# from azure.storage.blob import generate_container_sas, ContainerSasPermissions

# account_name = "xrdemo"
# account_key = "6ENSAfOyVGzLff0sOk8bsAspMnXYdju7OjjZefgshK9y+Xv387ZR0RpYXexCG6/i0bqOIcR6RTu/+AStTUrfDg=="
# container_name = "xrconnect-demo"

# # using generate_container_sas
# @mod_auth.route("/getsastoken")
# def get_sas_token():
#     container_sas_token = generate_container_sas(
#         account_name=account_name,
#         container_name=container_name,
#         account_key=account_key,
#         permission=ContainerSasPermissions(read=True,create=True, write=True, delete=True, list=False),
#         start=datetime.utcnow(),
#         expiry=datetime.utcnow() + timedelta(hours=1)
#     )
#     token=container_sas_token.replace('%3A', … Read more
# 3:11 PM
# YESTERDAY
# {
#     "Time taken": 0.005492448806762695,
#     "data": {
#         "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY0ODYxNzM1MCwianRpIjoiYjIxN2Q3YWItYjNhZC00NjBlLWE5MzYtNWM4MmRhYjQ3NjI4IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6eyJlbWFpbCI6Im5hcmF5YW5hcmFvQHJlaW52aXNpb24uY29tIiwidXNlcl9uYW1lIjoibmFyYXlhbmEiLCJnZW5kZXIiOiJNYWxlIiwicm9sZSI6IlN1cGVyQWRtaW4iLCJjb21wYW55IjoiWFJDT05ORUNUIiwic3lzdGVtX2lkIjpudWxsLCJsb2dpbl9zdGF0dXMiOm51bGwsInNhc190b2tlbiI6InN0PTIwMjItMDMtMzBUMDU6MTU6NTBaJnNlPTIwMjItMDMtMzBUMDY6MTU6NTBaJnNwPXJjd2Qmc3Y9MjAyMS0wNC0xMCZzcj1jJnNpZz1QM0hGOHlIZE02aTZvTVkvWkc5SUxhNVJVMEVoQlhBVWslMkJkTlpPZnFwb2slM0QifSwibmJmIjoxNjQ4NjE3MzUwLCJleHAiOjE2NDg2MTgyNTB9.BXmdM2H6gSCGw3mNFnQRw5lvQO2tdFFEasLh9FOvmuw",
#         "refresh_token": "e… Read more
# 10:46 AM
# {
#     "Time taken": 0.00561976432800293,
#     "data": {
#         "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY0ODYxNzY5MywianRpIjoiODQ2NWQ0YjctNTJjYS00MDM4LWE4MDEtZWZiZDQwZGU3ZDFmIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6eyJlbWFpbCI6Im5hcmF5YW5hcmFvQHJlaW52aXNpb24uY29tIiwidXNlcl9uYW1lIjoibmFyYXlhbmEiLCJnZW5kZXIiOiJNYWxlIiwicm9sZSI6IlN1cGVyQWRtaW4iLCJjb21wYW55IjoiWFJDT05ORUNUIiwic3lzdGVtX2lkIjpudWxsLCJsb2dpbl9zdGF0dXMiOm51bGwsInNhc190b2tlbiI6InN0PTIwMjItMDMtMzBUMDU6MjE6MzNaJnNlPTIwMjItMDMtMzBUMDY6MjE6MzNaJnNwPXJjd2Qmc3Y9MjAyMS0wNC0xMCZzcj1jJnNpZz1aT1FoMncwUENBU2txdy9rZ2t5V0RwR1FMQ3JwVzVUd0lMT2tlMmx2WnNNJTNEIn0sIm5iZiI6MTY0ODYxNzY5MywiZXhwIjoxNjQ4NjE4NTkzfQ.EEhSwqcyRF7KN4e6v37nbHw6gwqXU4M3vtMQXAzC9Xs",
#         "refresh_token": "eyJ0… Read more
# 10:52 AM
# token=urllib.parse.unquote(container_sas_token)
# 10:53 AM
# import urllib.parse
# 10:53 AM
# azure-storage-blob==12.10.0 pls add it to requirements.txt
# 2:26 PM
# TXT1 kB
# 2:47 PM
# TODAY
# account_name = "xrdemo"
# account_key = "6ENSAfOyVGzLff0sOk8bsAspMnXYdju7OjjZefgshK9y+Xv387ZR0RpYXexCG6/i0bqOIcR6RTu/+AStTUrfDg=="
# private_container_name = "xrconnect-demo"
# public_container_name = "public-container"

# using generate_private_container_sas
# @mod_auth.route("/getprivatesastoken")
# def get_private_sas_token():
#     container_sas_token = generate_container_sas(
#         account_name=account_name,
#         container_name=private_container_name,
#         account_key=account_key,
#         permission=ContainerSasPermissions(read=True,add=True,create=True, write=True, delete=True, list=True),
#         start=datetime.utcnow(),
#         expiry=datetime.utcnow() + timedelta(hours=24)
#     )
#     #token=container_sas_token.replace('%3A', ':')
#     token=urllib.parse.unquote(container_sas_token)
#     # blob_url_with_container_sas_token = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{container_sas_token}"
#     return f"{token}"

# using generate_public_container_sas
# @mod_auth.route("/getpublicsastoken")
# def get_public_sas_token():
#     container_sas_token = generate_container_sas(
#         account_name=account_name,
#         container_name=public_container_name,
#         account_key=account_key,
#         permission=ContainerSasPermissions(read=True,add=True, create=True, write=True, delete=True, list=True),
#         start=datetime.utcnow(),
#         expiry=datetime.utcnow() + timedelta(hours=24)
#     )
#     #token=container_sas_token.replace('%3A', ':')
#     token=urllib.parse.unquote(container_sas_token)
#     # blob_url_with_container_sas_token = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{container_sas_token}"
#     return f"{token}"

# using generate_public_container_sas
# @mod_auth.route("/checkpassword", methods=("GET", "POST"))
# def checkpassword():
#     password="Password@123"
#     password_hash=generate_password_hash(password, method="sha256")

#     return password_hash

'''
to delete the user , only SuperAdmin can have the permissions'''

@mod_auth.route('/deleteUser', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def deleteUsers():
    if request.method == 'POST':
        starttime=time.time()
        identity = get_jwt_identity()
        if identity['role'] == 'SuperAdmin':
            
            try:
                email = identity['email']
            except Exception as e:
                return make_response(
                    jsonify({"status": "fail", "message": str(e), "data": ""})
                )
            user = User.query.filter_by(email=email).first()

            if user is None:
                endtime=time.time()
                error = "No existing user"
                responseObject = {"status": "fail", "time taken":endtime - starttime ,"data": "", "message": error}
                return make_response(jsonify(responseObject))

            else:
                db.session.delete(user)
                db.session.commit()
                endtime=time.time()
                responseObject = {"status": "success", "data": email,
                                "message": f"User {email} deleted Successfully!","Time taken":endtime - starttime}
            return make_response(jsonify(responseObject))
        else:
            return make_response(jsonify({'status': 'fail', 'message': "you don't have the permission", 'data': ''}))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202


# User Details Update API
@mod_auth.route("/userUpdate", methods=('GET', 'POST', 'PUT'))
@jwt_required()
def userUpdate():
    if request.method == "PUT":
        starttime=time.time()
        Identity=get_jwt_identity()
        try:
            email = request.form["email"]
            firstname = request.form["FirstName"]
            lastname = request.form["LastName"]
            phonenumber = request.form["PhoneNumber"]
            username = request.form["UserName"]
            gender = request.form["Gender"]
            role = request.form["Role"]

        except Exception as e:
            return make_response(jsonify({"status": "fail", "message": str(e), "data": "Data is missing"}))

        user = User.query.filter_by(email=email).first()
        # refresh = create_refresh_token(identity=user.email)
        # access = create_access_token(identity=user.email)

        if not username:
            username = user.user_name
        else:
            username = username

        if not firstname:
            firstname = user.first_name
        else:
            firstname = firstname

        if not lastname:
            lastname = user.first_name
        else:
            lastname = lastname

        if not phonenumber:
            phonenumber = user.first_name
        else:
            phonenumber = phonenumber

        if not gender:
            gender = user.gender
        else:
            gender = gender

        if not role:
            role = user.role
        else:
            role = role

        if user.email is None:
            return "dat/api/v1/autha is missing"
        
        else:
            user.user_name = username
            user.first_name = firstname
            user.last_name = lastname
            user.phone_number = phonenumber
                # 'access':access,
            user.gender = gender
            user.role = role

            db.session.commit()
            endtime=time.time()

            responseObject = {
                "status": "success",
                "data": "",
                # 'refersh':refresh,
                # 'access':access,
                'Time taken':endtime - starttime,
                "message": f"User {email} details updated successfully!"
            }
        return make_response(jsonify(responseObject))
    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )


# Change password
@mod_auth.route("/changePassword", methods=("GET", "POST"))
@jwt_required()
def changePassword():
    if request.method == "POST":
        starttime=time.time()
        try:
            Identity=get_jwt_identity()
            email = request.form['email']
            print('user email=',email)
            oldpass = request.form['password']
            newpass = request.form['newpassword']
        except Exception as e:
            return make_response(jsonify({"status": "fail", "message": str(e), "data": "Entered Data is missing"}))

        error = None

        if not email and not oldpass and not newpass:
            return 'Enter valid details'
        else:
            user = User.query.filter_by(email=email).first()
            refresh = create_refresh_token(identity=user.email)
            access = create_access_token(identity=user.email)
            
            # firstname = (User.query(User.first_name).filter_by(email=email).first())
            print("user", user.email)
            if user is None:
                    endtime=time.time()
                    error="sorry, email is not listed!",
                    
                    return make_response(jsonify({"status": "fail", "message": error,"Time taken":endtime - starttime, "data": ""}))
            if not user.verify_password(oldpass):
                # error = "Whoops! Password do not match."
                error = "Entered old password is wrong."
                return make_response(jsonify({"status": "fail", "message": error, "data": ""}))
           
              
            else:
                user.password_hash = bcrypt.generate_password_hash(newpass).decode('utf-8')
                db.session.commit()
                message = 'Password successfully changed.'
               
                email_send(user.email, 9)
                endtime=time.time()
                return make_response(jsonify({"status": "success","Time taken":endtime - starttime ,  'access':access,
                'refersh':refresh,"message": message, "data": ""}))
    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )

# social user login
@mod_auth.route("/sociallogin", methods=("GET", "POST"))
def social_login():
    if request.method == "POST":
        starttime= time.time()
        try:
            email = request.form["email"]
            userName = request.form["userName"]
            imagePath = request.form["imagePath"]
            provider = request.form['provider']
            # isSocialUSer = request.form['isSocialUser']
            token = request.form['token']

        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(
                    e), "data": "Not working!"})
            )

        error = None

        if not email:
            error = 'Missing email'
        elif not userName:
            error = 'Missing userName'
        elif not imagePath:
            error = 'Missing imagePath'
        # elif not isSocialUSer:
        #     error = 'Missing isSocialUser'
        elif not provider:
            error = 'Missing provider'
        else:
            user = User.query.filter_by(email=email).first()
            refresh = create_refresh_token(identity=user.email)
            access = create_access_token(identity=user.email)
            print('user', user)
            if user is not None:
                error = "account already registered with this email."
                endtime=time.time()
                return make_response(
                    jsonify(
                        {
                            "status": "fail",
                            # "data": {"userData": new_user},
                            "message": error,
                            'Time taken':endtime - starttime
                        }
                    )
                )

        if error is None:
            default_password = "Password@123"
            new_user = User(
                email=email,
                password_hash=generate_password_hash(
                    default_password, method="sha256"),
                gender='undisclosed',
                role='User',
                company_name='undisclosed',
                token=token,
                is_active=1,
                user_name=userName,
                image_path=imagePath,
                is_social_user=True,
                provider=provider
            )
            db.session.add(new_user)
            db.session.commit()
            endtime= time.time()
            return make_response(
                jsonify(
                    {
                        "status": "success",
                        # "data": {"userData": new_user},
                        "message": " Login Success",
                        'access':access,
                        'refresh':refresh,
                        "Time taken":endtime - starttime
                    }
                )
            )
        else:
            return make_response(
                jsonify({"status": "fail", "message": error, "data": ""})
            )

    return make_response(
        jsonify({"status": "fail", "message": "Check method type.", "data": ""})
    )
    
    
    

'''
code for jwt , code by narayanarao dumpala
'''

            

#creating jwt refresh token for jwt access tokens

@mod_auth.route('/refreshtoken')
@jwt_required(refresh=True) 
def refresh_users_token():
    starttime=time.time()
    identity = get_jwt_identity()
    print('identity=',identity)
    access = create_access_token(identity=identity)
    endtime=time.time()

    return make_response(
        jsonify(
            {
                 "status": "success",
                 'access': access,
                 "message": " access token for refresh",
                 "Time taken":endtime - starttime
                 
             
             })
    )

# to identify the jwt token to whoome it accsess 
@mod_auth.route("/me")
@jwt_required()
def me():
    starttime=time.time() 
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    print('user=',user)
    endtime=time.time()
    return make_response({
        #'username': user.username,
        'email': user.email,
        "user_name":user.user_name,
        "phone":user.phone_number,
        "role":user.role,
        "gender":user.gender,
        "Time taken":endtime - starttime,
    })
    
 

#to create a sas token for azure bolob storage

from datetime import datetime, timedelta
from azure.storage.blob import generate_container_sas, ContainerSasPermissions

account_name = "xrdemo"
account_key = "6ENSAfOyVGzLff0sOk8bsAspMnXYdju7OjjZefgshK9y+Xv387ZR0RpYXexCG6/i0bqOIcR6RTu/+AStTUrfDg=="
private_container_name = "xrconnect-demo"
public_container_name = "public-container"
# using generate_private_container_sas
@mod_auth.route("/getprivatesastoken")
def get_private_sas_token():
    
    container_sas_token = generate_container_sas(
        account_name=account_name,
        container_name=private_container_name,
        account_key=account_key,
        permission=ContainerSasPermissions(read=True,add=True,
                                           create=True, write=True, delete=True, list=True),
        start=datetime.utcnow(),
        expiry=datetime.utcnow() + timedelta(hours=24)
    )
    #token=container_sas_token.replace('%3A', ':')
    token=urllib.parse.unquote(container_sas_token)
    # blob_url_with_container_sas_token = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{container_sas_token}"
    return f"{token}"
    
    
# using generate_public_container_sas
@mod_auth.route("/getpublicsastoken")
def get_public_sas_token():
    container_sas_token = generate_container_sas(
        account_name=account_name,
        container_name=public_container_name,
        account_key=account_key,
        permission=ContainerSasPermissions(read=True,add=True, create=True,
                                           write=True, delete=True, list=True),
        start=datetime.utcnow(),
        expiry=datetime.utcnow() + timedelta(hours=24)
    )
    #token=container_sas_token.replace('%3A', ':')
    token=urllib.parse.unquote(container_sas_token)
    # blob_url_with_container_sas_token = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{container_sas_token}"
    return f"{token}"

#using generate_public_container_sas
@mod_auth.route("/checkpassword", methods=("GET", "POST"))
def checkpassword():
    password="Password@123"
    #password=request.form['password']
    # password_hash=generate_password_hash(password, method="sha256")
    #password_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    #password_hash=generate_password_hash(password, method="sha256")
    data=bcrypt.check_password_hash(pw_hash,password)
    #data=bcrypt.hashpw(password, bcrypt.gensalt())
    if data:
        data= "true"
    else:
        data="false"
    return pw_hash +" " + data

#using generate_public_container_sas
@mod_auth.route("/verifypassword", methods=("GET", "POST"))
def verifypassword():
    #pw_hash="$2y$10$uf9kzIkxMRnh/y1NcAtCSuXJGd1WphWHTXD34h9k5iISAqw45r3/u"
    pw_hash="$2b$12$WFg9R.OFZWmMU4ZigVkOZ.CWUNJrYrgSvnfj/yaFbEDx5O.i9pXKG"
    password='Dspnnandu@123'
    data=bcrypt.check_password_hash(pw_hash,password).decode('utf-8')
    if data:
        data= "true"
    else:
        data="false"
    return data
'''
"//comment":"to access all the apis as in Swagger(Open API) Ui,swagger document  follwes the formatt off components and paths",
	"//secondcomment":"in place off components we maintain schemas , in scgemas we properties off the api parameeters",
	"//thirdcomment":"in place off paths we maintain which api path it has to call , in paths  we have tags,summary , description and response,tags represents the api module . summary and description represents about information about api request call ",


'''