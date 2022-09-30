from ctypes import string_at
import functools
import imp
from xrserver.mod_event.models import Event
#from datetime import time
from flask import jsonify, make_response, send_from_directory, send_file
from flask import stream_with_context, Response
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
import base64
from base64 import b64encode
from json import dumps
import io
import os
#import psutil
from werkzeug.utils import secure_filename
from pathlib import Path
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from xrserver import db, app

# Import module models
from .models import Media
import time 
import datetime
from .schemas import MediaSchema

mod_media = Blueprint('media', __name__, url_prefix='/media')

uploads_dir = os.path.join(app.instance_path, 'Assets')
from xrserver.mod_content_access.models import  contentAccess
# Add media formats (1: Video format, 2: GLTF format, 3: PDF format)


# Add Media with Azure URL
@mod_media.route("/addMediaAzure", methods=("GET", "POST"))
@jwt_required()
def addMediaAzure():
    if request.method == "POST":
        starttime=time.time()
        identity=get_jwt_identity()
        try:
            fileurl = request.form["FileURL"]
            filename = request.form['FileName']
            mediatype = request.form['MediaType']
            owner = request.form['CompanyName']
            uploadedby = request.form['UploadedBy']
            accesstype = request.form['AccessType']

        except Exception as e:
            return make_response(jsonify({"status": "fail", "message": str(e), "data": ""}))

        error = None
        if not fileurl:
            error = 'Missing "fileurl"'
        elif not mediatype:
            error = 'Missing "mediatype"'
        elif not owner:
            error = 'Missing "owner"'
        elif not uploadedby:
            error = 'Missing "uploadedby"'
        elif not accesstype:
            error = 'Missing "accesstype"'
        elif Media.query.filter_by(media_id=filename).first() is not None:
            error = 'Duplicate content'

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
            print(filename)
            media = Media()
            media.media_id = filename
            media.media_type = str(mediatype)
            media.owner = owner
            media.uploaded_by = uploadedby
            media.access_type = accesstype
            media.file_name =filename
            # media.fileurl = fileurl
            media.path = fileurl
            media.thumbnail_path = ""

            db.session.add(media)
            db.session.commit()
            endtime=time.time()
            responseObject = {
                'status': 'success',
                'message': 'Media uploaded',
                'data': fileurl,
                'Time taken':endtime - starttime,
                'user_idenrtity':identity
            }
            return make_response(jsonify(responseObject))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


# delete content file
@mod_media.route("/deleteContentFile", methods=("GET", "POST"))
@jwt_required()
def deleteContentFile():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['reole']=='SuperAdmin':
            try:
                media_id = request.form["mediaID"]
            except Exception as e:
                return make_response(
                    jsonify({"status": "fail", "message": str(e), "data": ""})
                )
            media = Media.query.filter_by(media_id=media_id).first()

            if media is None:
                error = "No existing content"
                endtime=time.time()
                responseObject = {"status": "fail", "data": "", "message": error,'Time taken':endtime - starttime}
                return make_response(jsonify(responseObject))

            else:
                db.session.delete(media)
                db.session.commit()
                endtime=time.time()
                responseObject = {"status": "success", "data": "", "message": "File deleted successfully.",'Time taken':endtime - starttime}
                return make_response(jsonify(responseObject))
        else:
            return make_response(jsonify({'status': 'fail', 'message': "sorry , you don'y have the permissions to delete the content", 'data': ''}))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''})), 202

#  new api for getting the selected content for the respective user

@mod_media.route('/getPrivateMediaList', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getPrivateMediaList():
    if request.method == "POST":
        starttime=time.time()
        identity=get_jwt_identity()
        try:
            email = request.form['email']

        except Exception as e:
            endtime=time.time()
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": "",'Time taken':endtime - starttime})
            )
        
        
        InvitePrivSelected = db.session.query(Media.media_id, Media.media_type, Media.description, Media.owner,Media.uploaded_by,Media.access_type,Media.permitted_users,Media.path,Media.file_name, contentAccess).join(contentAccess, (contentAccess.invitee_email == email) & (Media.media_id == contentAccess.content_id) & (Media.access_type== '2')).all()

        # b = Session.query.filter_by((Session.access_type =='public') | (Session.access_type =='private-1')).all()
        displayPrivateSelected = Media.query.filter_by(uploaded_by = email, access_type ='2').all()
        displayPrivate = Media.query.filter_by(access_type ='1').all()
        displayPublicAll = Media.query.filter_by(access_type ='0').all()
        
        result = InvitePrivSelected + displayPrivate + displayPublicAll + displayPrivateSelected

        if not result:
            error = "No Data Found"
            responseObject = {"status": "fail", "data": "", "message": error}
            return responseObject
        else:
            content_schema = MediaSchema()
            data = content_schema.dump(result,many = True)
            respData = {'contentsList' : data}
            endtime=time.time()
            responseObject = {
                'status': 'success',    
                'data': respData,
                'message' : ''       ,
                'time taken':endtime - starttime,
                'user_identity':identity  
            }
            return make_response(jsonify(responseObject))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

# Get Media List (0:All, 1:Video format, 2: GLBTF format, 3: PDF format)
@mod_media.route('/getMediaList', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getMediaList():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        try:
            mediatype = request.form['MediaType']
        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form data'}))
        
        error = None
        if not mediatype:
            error = 'Missing "mediatype"'

        if error is not None:
            print('MediaType error')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                'Time taken':endtime - starttime
            }    
            return make_response(jsonify(responseObject))
        else:
            if mediatype == "0":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).all()
                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True)
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': respData,
                        'message' : 'ALL files',
                        # 'user_identity':identity,
                        'Time taken':endtime - starttime
                    }  
                return make_response(jsonify(responseObject))
            elif mediatype == "1":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).filter_by(media_type=mediatype).all()
                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True)
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': respData,
                        'message' : 'Video files',
                        'Time taken':endtime - starttime,
                        #  'user_identity':identity
                    }  
                return make_response(jsonify(responseObject))
            elif mediatype == "2":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).filter_by(media_type=mediatype).all()
                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True)
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': respData,
                        'message' : 'GLTF files',
                        'Time taken':endtime - starttime,
                        #  'user_identity':identity
                    }  
                return make_response(jsonify(responseObject))
            elif mediatype == "3":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).filter_by(media_type=mediatype).all()

                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True )
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': data,
                        'message' : 'PDF Files',
                       'Time taken':endtime - starttime,
                        #  'user_identity':identity
                    }  
                    return make_response(jsonify(responseObject))
            else:
                return make_response(jsonify("File format not matched."))        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))        


# Get Media List (0:All, 1:Video format, 2: GLTF format, 3: PDF format)
@mod_media.route('/getMediaPaginationList', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getMediaPaginationList():
    if request.method == 'POST':
        startime=time.time()
        identity=get_jwt_identity()
        try:
            mediatype = request.form['MediaType']
        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form data'}))
        
        error = None
        if not mediatype:
            error = 'Missing "mediatype"'

        if error is not None:
            print('MediaType error')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                'Time taken':endtime - startime
            }    
            return make_response(jsonify(responseObject))
        else:
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('size', 5, type=int)
            if mediatype == "0":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).paginate(page=page, per_page=per_page,error_out=False)
                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True)
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': respData,
                        'message' : 'ALL files',
                         'user_identity':identity,
                         'Time taken':endtime - startime
                    }  
                return make_response(jsonify(responseObject))
            elif mediatype == "1":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).filter_by(media_type=mediatype).paginate(page=page, per_page=per_page,error_out=False)
                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True)
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': respData,
                        'message' : 'Video files',
                         'user_identity':identity,
                         'Time taken ':endtime - startime
                    }  
                return make_response(jsonify(responseObject))
            elif mediatype == "2":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).filter_by(media_type=mediatype).paginate(page=page, per_page=per_page,error_out=False)
                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True)
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': respData,
                        'message' : 'GLTF files',
                         'user_identity':identity,
                         'time taken':endtime - startime
                    }  
                return make_response(jsonify(responseObject))
            elif mediatype == "3":
                cons = db.session.query(Media.media_id,Media.media_type,Media.owner,Media.uploaded_by,Media.access_type,Media.path).filter_by(media_type=mediatype).paginate(page=page, per_page=per_page,error_out=False)

                if cons is not None :
                    media_schema = MediaSchema()
                    data = media_schema.dump(cons,many = True )
                    respData = {'contents' : data}
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',    
                        'data': data,
                        'message' : 'PDF Files',
                         'user_identity':identity,
                         'Time taken':endtime - startime
                    }  
                    return make_response(jsonify(responseObject))
            else:
                return make_response(jsonify("File format not matched."))        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))        

#to grab all records with respect to the searched item

@mod_media.route('/getSearchedMediaList',methods=('GET','POST'))
@jwt_required()
def getSearchedMediaList():
    if request.method== "POST":
        starttime=time.time()
        identity=get_jwt_identity()
        try:
         media_id=request.form['media_id']
        except Exception as e:
         return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing form data'}))
        error=None
        if not media_id:
            error="Missing 'media_id'"

        if error is not None:
            print('MediaType error')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data': '',
                'Time taken':endtime - starttime
            }
            return make_response(jsonify(responseObject))
        else:
            results = Media.query.filter(Media.media_id.like('%'+media_id+'%')).all()
            print('media results=',results)
            if not results:
                error = "No Data Found"
                responseObject = {"status": "fail", "data": "", "message": error}
                return responseObject
            else:
                content_schema = MediaSchema()
                data = content_schema.dump(results, many=True)
                respData = {'contentsList': data}
                # refresh = create_refresh_token(identity='user')
                # access = create_access_token(identity='user')
                ebdtime=time.time()
                responseObject = {
                    'status': 'success',
                    'data': respData,
                    'message': '',
                    # 'access':access,
                    # 'refresh':refresh,
                    
                         'user_identity':identity,
                         'Time taken':endtime - starttime
                }
                return make_response(jsonify(responseObject))
            # if results is None:
            #     error = "No existing media"
            #     responseObject = {"status": "fail", "data": "", "message": error}
            #     return make_response(jsonify(responseObject))
            #
            # else:
            #     user_schema = MediaSchema()
            #     data = user_schema.dump(results,many=True)
            #     responseObject = {"status": "success", "data": data, "message": ""}
            # return make_response(jsonify(responseObject))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))