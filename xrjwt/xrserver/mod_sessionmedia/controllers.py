from ctypes import string_at
import functools
#from datetime import time
from flask import jsonify, make_response
import mysql.connector
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from xrserver import db
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# Import module models
from .models import SessionMedia
import time
from .schemas import SessionMediaSchema

mod_session_media = Blueprint('session_media', __name__, url_prefix='/sessionmedia')

@mod_session_media.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def content():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']=='SuperAdmin':
            try :
                eventID = request.form['EventID']
                mediaID = request.form['MediaID']
                mediaType = request.form['MediaType']
                media_path = request.form['MediaPath']

            except Exception as e:
                return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing form data'}))

            error = None
            if not eventID:
                error = 'Missing "EventID"'
            elif not mediaID:
                error = 'Missing "MediaID"'
            # elif not media_path:
            #     error = 'Missing MediaPath'
            elif SessionMedia.query.filter_by(media_id=mediaID, session_id=eventID).first() is not None:
                # error = 'Duplicate content'
                print(SessionMedia.query.filter_by(
                    media_id=mediaID, session_id=eventID).first())
                error = eventID + ' Duplicate values in session media ' + mediaID

            if error is not None:
                print('sending fail status')
                endtime=time.time()
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data': '',
                    'Time taken':endtime - starttime
                    
                }
                return make_response(jsonify(responseObject))

            else:
                content = SessionMedia()
                content.session_id = eventID
                content.media_id = mediaID
                content.media_type = mediaType
                content.media_path = media_path

                db.session.add(content)
                db.session.commit()
                endtime=time.time()
                
                responseObject = {
                    'status': 'success',
                    'message': 'Content Added Successfully.',
                    'data': '',
                    'Time taken':endtime -starttime
                   
                }
                return make_response(jsonify(responseObject))
        else:
         return  make_response(jsonify({'status':'fail', 'message' : "sorry , you don't have the permissions,only SuperAdmin can do this operation",'data': ''}))
         

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


@mod_session_media.route('/get', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getcontent():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']=='SuperAdmin':
            try:
                eventID = request.form['EventID']

            except Exception as e:
                return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing form data'}))

            error = None
            if not eventID:
                eventID = 'Missing "eventID"'

            print('videos for event id ' + eventID)
            if error is not None:
                print('sending fail status')
                endtime=time.time()
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data': '',
                    'Time taken':endtime - starttime}
                return make_response(jsonify(responseObject))

            else:
                con = db.session.query(SessionMedia.media_id).filter_by(
                    session_id=eventID).all()

                #con = SessionMedia.query.filter_by(session_id=eventID).all()
                # print(con[0].media_type)
                # print(con[1].media_type)

                if not con:
                    return make_response(jsonify({'status': 'fail', 'message': 'Data with given event ID not found', 'data': ''}))
                else:
                    schema = SessionMediaSchema()
                    data = schema.dump(con, many=True)
                    endtime=time.time()
                    
                    responseObject = {
                            'status': 'success',
                            'message': 'session media retrieved sucessfully',
                            'data' : data,
                            'Time taken':endtime -starttime
                            
                        }
                    return make_response(jsonify(responseObject))
        else:
                
          return  make_response(jsonify({'status':'fail', 'message' : "sorry , you don't have the permissions,only SuperAdmin can do this operation",'data': ''}))
         
         

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


def deleteSessionMedia(sessionID):
    con = SessionMedia.query.filter_by(session_id=sessionID).all()
    print('Deleting records for ' + sessionID)
    #query = SessionMedia.delete().where(session_id=sessionID)
    for obj in con:
        db.session.delete(obj)
        db.session.commit()
    # query.execute()


@mod_session_media.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def v2content():
    if request.method == 'POST':
        startime=time.time()
        identity=get_jwt_identity()
        if identity['role']=='SuperAdmin':
            try:
                eventID = request.form['EventID']
                mediaID = request.form['MediaID']
                mediaType = request.form['MediaType']
                media_path = request.form['MediaPath']

            except Exception as e:
                return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing form data'}))

            error = None
            if not eventID:
                error = 'Missing "EventID"'
            elif not mediaID:
                error = 'Missing "MediaID"'
            # elif not media_path:
            #     error = 'Missing MediaPath'
            elif SessionMedia.query.filter_by(media_id=mediaID, session_id=eventID).first() is not None:
                # error = 'Duplicate content'
                print(SessionMedia.query.filter_by(
                    media_id=mediaID, session_id=eventID).first())
                error = eventID + ' Duplicate values in session media ' + mediaID

            if error is not None:
                print('sending fail status')
                endtime=time.time()
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data': '',
                    'Time taken':endtime - startime
                }
                return make_response(jsonify(responseObject))

            else:
                content = SessionMedia()
                content.session_id = eventID
                content.media_id = mediaID
                content.media_type = mediaType
                content.media_path = media_path

                db.session.add(content)
                db.session.commit()
                endtime=time.time()
                responseObject = {
                    'status': 'success',
                    'message': 'media added Successfully.',
                    'data': '',
                    'Time taken':endtime - startime
                
                }
                return make_response(jsonify(responseObject))
        else:
                
          return  make_response(jsonify({'status':'fail', 'message' : "sorry , you don't have the permissions,only SuperAdmin can do this operation",'data': ''}))
         
        
            
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))
