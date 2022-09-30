from ctypes import string_at
import functools
#from datetime import time
from flask import jsonify, make_response
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from xrserver import db
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# Import module models
from .models import PermittedUsers
import time
from .schemas import PermittedUsersSchema

mod_permitted_users = Blueprint('permitted_users', __name__, url_prefix='/permittedusers')

@mod_permitted_users.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def content():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        try :
            eventID = request.form['EventID']
            contentID = request.form['ContentID']
            media_id=request.form['media_id']
            user_email=request.form['user_email']

        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form data'}))

        error = None
        if not eventID:
            error = 'Missing "eventID"'
        elif not contentID:
            error = 'Missing "contentID"'
        elif not media_id :
            error = 'Missing "media_id"'
        elif not user_email :
            error = 'Missing "user_email"'
        elif PermittedUsers.query.filter_by(content_id=contentID, session_id=eventID).first() is not None : 
            error = 'Duplicate content'
       
        if error is not None:
            endtime=time.time()
            print('sending fail status')
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                'Time taken':endtime - starttime
            }    
            return make_response(jsonify(responseObject))

        else:
            content = PermittedUsers()
            content.session_id = eventID
            content.content_id = contentID
            content.media_id=media_id
            content.user_email=user_email
            db.session.add(content)
            db.session.commit()
            # refresh = create_refresh_token(identity=user_email)
            # access = create_access_token(identity=user_email)
            endtime=time.time()
            responseObject = {
                'status': 'success',
                'message': 'Data added',
                'data' : '',
                # 'refresh':refresh,
                # 'access':access,
                'Time taken':endtime - starttime
            }
            return make_response(jsonify(responseObject))
            
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

@mod_permitted_users.route('/get', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getcontent():
    if request.method == 'POST':
        identity=get_jwt_identity()
        starttime=time.time()
        try :
            eventID = request.form['EventID']

        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form data'}))

        error = None
        if not eventID:
            eventID = 'Missing "eventID"'
        
        if error is not None:
            print('sending fail status')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : ''   ,
                'Time taken':endtime -starttime
                }     
            return make_response(jsonify(responseObject))

        else:
            con = PermittedUsers.query.filter_by(session_id=eventID).all()
            
            if not con:
                return make_response(jsonify({'status':'fail', 'message' : 'Data with given event ID not found','data': ''}))
            else:
                schema = PermittedUsersSchema()
                data = schema.dump(con,many=True)
                # refresh = create_refresh_token(identity='user')
                # access = create_access_token(identity='user')
                endtime=time.time()
                responseObject = {
                        'status': 'success',
                        'message': 'session contents data retrieved sucessfully',
                        'data' : data,
                        # 'access':access,
                        # 'refresh':refresh
                        'Time taken':endtime - starttime
                    }
                return make_response(jsonify(responseObject))

            
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))
