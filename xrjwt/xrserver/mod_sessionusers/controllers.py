import functools
#from datetime import time
from flask import jsonify, make_response
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity

from xrserver import db
########### Siddharth ###########
from ..mailsetup import email_send
########### Siddharth ###########
# Import module models
from .models import SessionUsers

from .schemas import SessionUsersSchema
import time
mod_session_users = Blueprint('session_users', __name__, url_prefix='/session_users')

@mod_session_users.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def addSessionUsers():
    global sessionid
    if request.method == 'POST':
        identity=get_jwt_identity()
        starttime=time.time()
        try:
            sessionid = request.form['SessionID']
            userid = request.form['UserID']
            userrole = request.form['UserRole']
            useravatar = request.form['UserAvatar']
            eventid=request.form['eventid']
            isfav = request.form['IsFavourite']
        except Exception as e:
            return make_response(jsonify({'status':'fail', 'message' : str(e),'data': 'Entry in form data missing'}))
        
        error = None
        print('sessionid '+ sessionid)
        if not sessionid:
            error = 'Missing "SessionID"'
        elif not userid:
            error = 'Missing "UserID"'
        elif not userrole:
            error = 'Missing "UserRole"'
        elif not useravatar:
            useravatar = 'Default'
        elif not isfav:
            isfav = 0
        
        if error is None:
            sessionuser = SessionUsers()
            sessionuser.session_id = sessionid
            sessionuser.user_id = userid
            sessionuser.user_role = userrole
            sessionuser.user_avatar = useravatar
            sessionuser.is_favourite = isfav
            sessionuser.eventid=eventid

            db.session.add(sessionuser)
            db.session.commit()
            endtime=time.time()
            responseObject = {
                    'status': 'success',
                    'message': 'session user data added sucessfully',
                    'data' : '',
                    'Time taken':endtime - starttime
                   
                }
            email_send(userid, 5)
            return make_response(jsonify(responseObject))

        else:
            endtime=time.time()
            return make_response(jsonify({'status':'fail', 'message' : error,'data': '','Time taken':endtime - starttime}))

    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


@mod_session_users.route('/get', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getSessionUsers():
    identity=get_jwt_identity()
    if request.method == 'POST':
        starttime=time.time()
        try:
            sessionid = request.form['SessionID']

        except Exception as e:
            return make_response(jsonify({'status':'fail', 'message' : str(e),'data': 'Entry in form data missing'}))
        
        error = None
        if not sessionid:
            error = 'Missing "SessionID"'

        if error is None:
            ses = SessionUsers.query.filter_by(session_id=sessionid).all()

            if ses is None:
                endtime=time.time()
                return make_response(jsonify({'status':'fail', 'message' : error,'data': '','Time taken':endtime - starttime}))
            else:
                schema = SessionUsersSchema()
                data = schema.dump(ses,many=True)
                endtime=time.time()
                responseObject = {
                        'status': 'success',
                        'message': 'session user data retrieved sucessfully',
                        'data' : data,
                        'Time taken':endtime - starttime
                       
                    }
                return make_response(jsonify(responseObject))

        else:
            endtime=time.time()
            return make_response(jsonify({'status':'fail', 'message' : error,'data': '','Time taken':endtime - starttime}))

    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


@mod_session_users.route('/getUserSessions', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getUserSessions():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        
        try:
            userid = request.form['UserID']
            print(userid)

        except Exception as e:
            return make_response(jsonify({'status':'fail', 'message' : str(e),'data': 'Entry in form data missing'}))
        
        error = None
        if not userid:
            error = 'Missing "UserID"'

        if error is None:
            ses = SessionUsers.query.filter_by(user_id=userid).all()
           

            if ses is None:
                endtime=time.time()
                return make_response(jsonify({'status':'fail', 'message' : error,'data': '','Time taken':endtime - starttime}))
            
            else:
                schema = SessionUsersSchema()
                data = schema.dump(ses,many=True)
                endtime=time.time()
                responseObject = {
                        'status': 'success',
                        'message': 'user sessions data retrieved sucessfully',
                        'data' : data,
                        'user_identity':identity,
                        'Time taken':endtime - starttime
                        
                    }
                return make_response(jsonify(responseObject))

        else:
            endtime=time.time()
            return make_response(jsonify({'status':'fail', 'message' : error,'data': '','Time taken':endtime - starttime}))

    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


@mod_session_users.route('/update',  methods=('GET', 'POST', 'PUT'))
@jwt_required()
def update():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']=='SuperAdmin':
            try:
                sessionid = request.form['SessionID']
                userid = request.form['UserID']
                userrole = request.form['UserRole']
                useravatar = request.form['UserAvatar']
                isfavourite = request.form['IsFavourite']
            except Exception as e:
                return make_response(jsonify({'status':'fail', 'message' : str(e),'data': 'Entry in form data missing'}))
            
            error = None
            
            if not sessionid:
                error = 'Missing "SessionID"'
            elif not userid:
                error = 'Missing "UserID"'

            print("No error \n" + sessionid +"\n"+userid)
            if error is None:
                try :
                    ses = SessionUsers.query.filter_by(session_id=sessionid,user_id=userid).first()
                    #ses = db.session.query().filter_by(session_id=sessionid, user_id=userid)
                except Exception as e:
                    return make_response(jsonify({'status':'fail', 'message' : str(e),'data': 'Query exception'}))

                print("Ses found " + str(ses is None))
                
                if ses is not None:
                    ses.user_avatar = useravatar
                    ses.is_favourite = isfavourite
                    ses.user_role = userrole
            
                    db.session.commit()
                    endtime=time.time()
                    return make_response(jsonify({'status':'success', 'message' : 'Updated session user data','data': '','Time taken':endtime - starttime}))
                else:
                    endtime=time.time()
                    return make_response(jsonify({'status':'fail', 'message' : 'Session user not found','data': '','Time taken':endtime - starttime}))
        else:
            
                
          return  make_response(jsonify({'status':'fail', 'message' : "sorry , you don't have the permissions,only SuperAdmin can do this operation",'data': ''}))
         
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))