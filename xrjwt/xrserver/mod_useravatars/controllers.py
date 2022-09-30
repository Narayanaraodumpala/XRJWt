import functools
#from datetime import time
from flask import jsonify, make_response, send_from_directory, send_file
from flask import stream_with_context, Response
from base64 import b64encode

from json import dumps
import io
import os
from werkzeug.utils import secure_filename
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from xrserver import db,app
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# Import module models
from .models import UserAvatars

from .schemas import UserAavatarsSchema
import time
mod_useravatars = Blueprint('avatars', __name__, url_prefix='/avatars')

uploads_dir = os.path.join(app.instance_path, 'Assets')


@mod_useravatars.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()

def addAvatar():
    if request.method == 'POST':
        identity=get_jwt_identity()
        startime=time.time()
        print(request.method)
        try :
            #avatarID = request.files['AvatarID']
            modelFile = request.files['ModelFile']
            userID = request.form['UserID']

        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form data'}))

        error = None
        
        if not userID :
            error = 'Missing "UserID"'
        # if not avatarID :
        #     error = 'Missing "AvatarID"'
        if not modelFile :
            error = 'Missing "ModelFile"'
        elif UserAvatars.query.filter_by(user_id=userID).first() is not None:
            error = "Duplicate data"

        if error is not None:
            print('sending fail status')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                'Time taken':endtime - startime
            } 
            return make_response(jsonify(responseObject))
        
        try:
            print ('No errors... uploading avatar file.')
                
            dir_new = os.path.join(uploads_dir , 'Avatars')            
            if not os.path.exists(dir_new) :
                os.mkdir(dir_new)

            avatar_dir = os.path.join(dir_new,userID)
            if not os.path.exists(avatar_dir) :
                os.mkdir(avatar_dir)

            print('Zip name is : '+modelFile.filename)
            path = os.path.join(avatar_dir, secure_filename(modelFile.filename))
            modelFile.save(path)  
               
            print ('files uploaded successfully')
                
        except :
            print ('file upload fail')
            error = 'File upload failed.'

        if error is not None:
            print('sending fail status')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                'Time taken':endtime - startime
            }    
    
            return make_response(jsonify(responseObject))
        
        else:
            avatar = UserAvatars()
            avatar.user_id = userID
            avatar.model_file_path = path
            #avatar.avatar_id = avatarID

            db.session.add(avatar)
            db.session.commit()
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            endtime=time.time()
            responseObject = {
                'status': 'success',
                'message': 'avatar uploaded',
                'data' : '',
                'Time taken':endtime - startime
                # 'access':access,
                # 'refresh':refresh
            }
            return make_response(jsonify(responseObject))
        

    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

        
@mod_useravatars.route('/get', methods=('GET', 'POST', 'PUT'))
def getFile():
    if request.method == 'POST':
        starttime=time.time()
        try :
            userID = request.form['UserID']
        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : 'Missing form data'}))

        con = UserAvatars.query.filter_by(user_id=userID).first()
        
        error = None
        
        if con is None :
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            error = 'No existing content'
            endttime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                'Time taken':endttime - starttime
                # 'access':access,
                # 'refresh':refresh
            }            
            return make_response(jsonify(responseObject))
       
        else:
            modeldata = getFile(con.model_file_path)
            file_name = os.path.basename(con.model_file_path)
            print(file_name)
            endtime=time.time()
            responseObject = {
                'status' : 'success', 
                'message':os.path.splitext(file_name)[0], 
                'data': modeldata,
                'Time taken':endtime - starttime
                }

            resp = make_response(jsonify(responseObject))
            return resp

    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


def getFile(filepath):
    rv = send_file(filepath)
    rv.direct_passthrough = False
    filedata = b64encode(rv.data).decode('ascii')
    return filedata