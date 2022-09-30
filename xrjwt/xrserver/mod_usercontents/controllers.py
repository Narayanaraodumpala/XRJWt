from ctypes import string_at
import functools
# from datetime import time
from flask import jsonify, make_response, send_from_directory, send_file
from flask import stream_with_context, Response

import base64
from base64 import b64encode
from json import dumps
import io
import os
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# import psutil
from werkzeug.utils import secure_filename
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from xrserver import db, app
import time
# Import module models
from .models import UserContents
from ..mod_contents.models import Content

from .schemas import UserContentsSchema

mod_usercontents = Blueprint(
    'user_contents', __name__, url_prefix='/usercontents')

uploads_dir = os.path.join(app.instance_path, 'Assets')


@mod_usercontents.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def DynamicContent():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity
        if identity ['role'] == 'SuperAdmin':
            try:
                # cid = request.form['ContentID']
                contentname = request.form['ContentName']
                contenttype = request.form['ContentType']
                # contentloadtype = request.form['ContentLoadType']
                version = request.form['Version']
                buildtarget = request.form['BuildTarget']
                buildversion = request.form['BuildVersion']
                polyVersion = request.form['PolyVersion']
                f = request.files['assetFileUrl']
                shaderFile = request.files['shaderFileUrl']
                hashFile = request.files['hashFileUrl']
                jsonFile = request.files['jsonFileUrl']
                # thumbf = request.files['thumbnailFile']
                description = request.form['Description']
                owner = request.form['Owner']
                accesstype = request.form['AccessType']
                uploadedBy = request.form['uploadedBy']
                assetFileName = request.form['assetFileName']
                shaderFileName = request.form['shaderFileName']
                hashFileName = request.form['hashFileName']
                jsonFileName = request.form['jsonFileName']

            except Exception as e:
                return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing Entry'}))

            error = None
            thumbnail_error = None
            path = None

            # if not cid :
            #     error = 'Missing "ContentID"'
            # else:
            #     contentid = contentname+'_EXT'
            if not contenttype:
                error = 'Missing "ContentType"'
            else:
                if contenttype == "1":
                    contentloadtype = "1"
                else:
                    contentloadtype = "2"
            # if not contentloadtype:
            #     error = 'Missing "ContentLoadType"'
            if not contentname:
                error = 'Missing "ContentName"'
            else:
                contentid = contentname+'_EXT'
            if not owner:
                error = 'Missing "Owner"'
            elif not accesstype:
                error = 'Missing "AccessType"'
            elif not version:
                error = 'Missing "Version"'
            elif not buildtarget:
                error = 'Missing "BuildTarget"'
            elif not buildversion:
                error = 'Missing "BuildVersion"'
            elif not polyVersion:
                error = 'Missing "PolyVersion"'
            elif not f:
                error = 'Missing "file"'
            elif not shaderFile:
                error = 'Missing "ShaderFile"'
            elif not hashFile:
                error = 'Missing "HashFile"'
            elif not jsonFile:
                error = 'Missing "Jsonfile"'
            elif not uploadedBy:
                error = 'Missing Uploaded By'
            print(contentid)
            duplicates = UserContents.query.filter_by(
                content_id=contentid, content_name=contentname, build_target=buildtarget).first()

            if duplicates is not None:
                error = 'Duplicate content'

            duplicates = Content.query.filter_by(
                content_id=contentname, build_target=buildtarget).first()

            if duplicates is not None:
                error = 'Duplicate content'

            if error is None:
                try:
                    print('No errors... uploading file.')

                    dir_new = os.path.join(uploads_dir, buildversion)
                    CreateDirectory(dir_new)

                    dir_new_buildtarget = os.path.join(dir_new, buildtarget)
                    CreateDirectory(dir_new_buildtarget)

                    poly_path = os.path.join(dir_new_buildtarget, polyVersion)
                    CreateDirectory(poly_path)

                    file_path = os.path.join(poly_path, contentname)
                    CreateDirectory(file_path)

                    content = UserContents()
                    content.content_id = contentid
                    content.content_name = contentname
                    content.content_type = contenttype
                    content.content_load_type = contentloadtype
                    content.owner = owner
                    content.access_type = accesstype
                    content.build_target = buildtarget
                    content.version = version
                    content.uploaded_by = uploadedBy
                    content.thumbnail_path = app.config['UPLOAD_FOLDER']
                    if description:
                        content.description = description

                    UploadFile(f, content, file_path, assetFileName)
                    UploadFile(hashFile, content, file_path, hashFileName)
                    UploadFile(jsonFile, content, file_path, jsonFileName)
                    UploadFile(shaderFile, content, file_path, shaderFileName)
                    # refresh = create_refresh_token(identity='user')
                    # access = create_access_token(identity='user')

                    # print('file uploaded successfully')

                    # print('Sucess')
                    msg = 'upload sucess'
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',
                        'message': msg,
                        'data': '',
                        # 'access':access,
                        # 'refresh':refresh
                        'Time taken':endtime - starttime
                    }
                    return make_response(jsonify(responseObject))

                except Exception as e:
                    print('file upload fail  '+str(e))
                    error = 'File upload failed. Change content ID'
                    endttime=time.time()
                    responseObject = {
                        'status': 'fail',
                        'message': error,
                        'data': '',
                        'Time taken':endtime - starttime
                    }

                return make_response(jsonify(responseObject))

            else:
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
            return  make_response(jsonify({'status': 'fail', 'message': "sorry, You are not SuperAdmin, so you don't have permission to do this operation", 'data': ''}))



    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


def UploadFile(f, content, path, fileName):
    newContent = UserContents()
    newContent.content_id = content.content_id
    newContent.content_name = content.content_name
    newContent.content_type = content.content_type
    newContent.content_load_type = content.content_load_type
    newContent.owner = content.owner
    newContent.access_type = content.access_type
    newContent.build_target = content.build_target
    newContent.version = content.version
    newContent.thumbnail_path = content.thumbnail_path
    newContent.description = content.description
    newContent.uploaded_by = content.uploaded_by
    newContent.file_name = fileName

    path = os.path.join(path, secure_filename(f.filename))
    print('uploading  to ' + path)
    f.save(path)
    print('file uploaded')
    newContent.path = path
    newContent.file_name = f.filename
    print('content edited '+str(newContent))
    db.session.add(newContent)
    db.session.commit()
    print('content data committed to db')


def CreateDirectory(path):
    if not os.path.exists(path):
        print('Creating folder' + path)
        os.mkdir(path)


@mod_usercontents.route('/get', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def GetContent():
    if request.method == 'POST':
        
        starttime=time.time()
        identity=get_jwt_identity()
        try:
            contentID = request.form['ContentID']
            buildTarget = request.form['BuildTarget']
        except Exception as e:
            return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing Entry'}))
        error = None

        if not contentID:
            error = 'Missing "ContentID"'
        if not buildTarget:
            error = 'Missing "BuildTarget"'

        if error is not None:
            return make_response(jsonify({'status': 'fail', 'message': '', 'data': error}))

        con = db.session.query(UserContents.content_id, UserContents.file_name).filter_by(
            content_id=contentID, build_target=buildTarget).all()
        if con is not None:
            schema = UserContentsSchema()
            data = schema.dumps(con, many=True)
            responseData = {'contents': data}
            print(responseData)
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            endtime=time.time()
            responseObject = {
                'status': 'success',
                'message': '',
                'data': responseData,
                # 'access':access,
                # 'refresh':refresh,
                'Time taken':endtime - starttime
            }
            return make_response(responseObject)

        else:
            return make_response(jsonify({'status': 'fail', 'message': '', 'data': 'Requested data not found'}))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


@mod_usercontents.route('/getFile', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def GetContentFile():
    if request.method == 'POST':
        
        starttime=time.time()
        identity=get_jwt_identity()
        try:
            contentID = request.form['ContentID']
            filename = request.form['FileName']
            polyVersion = request.form['PolyVersion']
            buildTarget = request.form['BuildTarget']
            buildVersion = request.form['BuildVersion']

        except Exception as e:
            return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': 'Missing Entry'}))

        error = None
        if not contentID:
            error = 'Missing "ContentID"'
        elif not filename:
            error = 'Missing "FileName"'
        elif not polyVersion:
            error = 'Missing "PolyVersion"'
        elif not buildTarget:
            error = 'Missing "BuildTarget"'
        elif not buildVersion:
            error = 'Missing "BuildVersion"'

        if error is not None:
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            endtime=time.time()
            return make_response(jsonify({'status': 'fail','Time taken':endtime - starttime, 'message': '', 'data': error}))

        con = UserContents.query.filter_by(
            content_id=contentID, build_target=buildTarget, file_name=filename).first()

        if con is not None:
            try:
                path = os.path.join(uploads_dir, buildVersion, buildTarget,
                                    polyVersion, con.content_name, con.file_name)
                print('downloading file ' + path)
                rv = send_file(path)
                rv.direct_passthrough = False
                print('received file from server')
                return rv

            except Exception as e:
                print('exception ' + str(e))
                error = str(e)
                # refresh = create_refresh_token(identity='user')
                # access = create_access_token(identity='user')
                return make_response(jsonify({'status': 'fail', 'message': str(e), 'data': ''}))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


# Add addressable with Azure URL
@mod_usercontents.route("/addAddressableAzure", methods=("GET", "POST"))
@jwt_required()
def addAddressableAzure():
    if request.method == "POST":
        starttime=time.time()
        identity=get_jwt_identity()
        if identity ['role']=='SuperAdmin':
            try:
                contentname = request.form['ContentName']
                contenttype = request.form['ContentType']
                version = request.form['Version']
                buildtarget = request.form['BuildTarget']
                buildversion = request.form['BuildVersion']
                polyVersion = request.form['PolyVersion']
                description = request.form['Description']
                owner = request.form['Owner']
                accesstype = request.form['AccessType']
                file = request.form['assetFileUrlassetFileUrl,']
                shaderFile = request.form['shaderFileUrl']
                hashFile = request.form['hashFileUrl']
                jsonFile = request.form['jsonFileUrl']
                uploadedBy = request.form['uploadedBy']
                assetFileName = request.form['assetFileName']
                shaderFileName = request.form['shaderFileName']
                hashFileName = request.form['hashFileName']
                jsonFileName = request.form['jsonFileName']
                print('file name in 321', file)

            except Exception as e:
                return make_response(jsonify({"status": "fail", "message": str(e), "data": ""}))

            error = None

            if not contenttype:
                error = 'Missing "ContentType"'
            else:
                if contenttype == "1":
                    contentloadtype = "1"
                else:
                    contentloadtype = "2"
            if not contentname:
                error = 'Missing "ContentName"'
            else:
                contentid = contentname + '_EXT'
            if not contenttype:
                error = 'Missing "contenttype"'
            elif not version:
                error = 'Missing "version"'
            elif not buildtarget:
                error = 'Missing "buildtarget"'
            elif not description:
                error = 'Missing "description"'
            elif not owner:
                error = 'Missing "owner"'
            elif not accesstype:
                error = 'Missing "accesstype"'
            elif not file:
                error = 'Missing "file"'
            elif not shaderFile:
                error = 'Missing "shaderFile"'
            elif not hashFile:
                error = 'Missing "hashFile"'
            elif not jsonFile:
                error = 'Missing "jsonFile"'
            elif not uploadedBy:
                error = 'Missing Uploaded By'
            externalDuplicates = UserContents.query.filter_by(
                content_id=contentid, content_name=contentname, build_target=buildtarget).all()
            if externalDuplicates:
                error = 'Duplicate external content'
                print('in external duplicates', externalDuplicates)
                for record in externalDuplicates:
                    print('duplicate record', record)
                    db.session.delete(record)
                    db.session.commit()
                # db.session.delete(duplicates)
                # db.session.commit()

                error = None

            internalDuplicates = Content.query.filter_by(
                content_id=contentname, build_target=buildtarget).first()

            if internalDuplicates:
                error = 'Duplicate external content'
                print('in internal duplicates',internalDuplicates)
                for record in internalDuplicates:
                    print('duplicate record', record)
                    db.session.delete(record)
                    db.session.commit()
                # db.session.delete(duplicates)
                # db.session.commit()

                error = None

            if error is None:
                try:
                    print(' in 393 No errors... uploading file.')
                    content = UserContents()
                    content.content_id = contentid
                    content.content_name = contentname
                    content.content_type = contenttype
                    content.version = version
                    content.build_target = buildtarget
                    content.owner = owner
                    content.access_type = accesstype
                    content.content_load_type = contentloadtype
                    content.uploaded_by = uploadedBy
                    if description:
                        content.description = description

                    UploadFile(file, content, assetFileName)
                    UploadFile(hashFile, content, hashFileName)
                    UploadFile(jsonFile, content, jsonFileName)
                    UploadFile(shaderFile, content, shaderFileName)
                    print('file uploaded successfully')
                    # refresh = create_refresh_token(identity='user')
                    # access = create_access_token(identity='user')
                    endtime=time.time()
                    responseObject = {
                        'status': 'success',
                        'message': 'upload success',
                        'data': '',
                        # 'access':access,
                        # 'refresh':refresh,
                        'Time taken':endtime - starttime
                    }
                    return make_response(jsonify(responseObject))
                except Exception as e:
                    print('file upload fail  '+str(e))
                    error = 'File upload failed. Change content Name'
                    endttime=time.time()
                    responseObject = {
                        'status': 'fail',
                        'message': error,
                        'data': '',
                        'Time taken':endtime - starttime
                    }

                return make_response(jsonify(responseObject))
            else:
                print(' in 435  fail status')
                endtime=time.time()
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data': '',
                    'Time taken':endtime - starttime
                }

                return make_response(jsonify(responseObject))
        else:
            return make_response(jsonify({'status': 'fail', 'message': "sorry, You don't have the permissions", 'data': ''}))

    return make_response(jsonify({'status': 'fail', 'message': 'check method type.', 'data': ''}))


def UploadFile(file, content, fileName):
    # print('file name in upload file 428',content.content_name)
    newContent = UserContents()
    newContent.content_id = content.content_id
    newContent.content_name = content.content_name
    newContent.content_type = content.content_type
    newContent.version = content.version
    newContent.build_target = content.build_target
    newContent.description = content.description
    newContent.owner = content.owner
    newContent.access_type = content.access_type
    newContent.content_load_type = content.content_load_type
    newContent.path = file
    newContent.uploaded_by = content.uploaded_by
    newContent.file_name = fileName

    # res = str(file).rpartition('%2F')
    # print('res 445',res,content)
    # newContent.file_name = str(res[-1])
    # print('file name',newcontent.file_name)
    # print("new data ", newcontent.content_id, newcontent.content_name, newcontent.file_name, newcontent.path)
    # print('uploading to ' + file)
    # print('file uploaded')

    db.session.add(newContent)
    db.session.commit()
    print('Content data committed to db')


# @mod_usercontents.route('/getObjectList', methods=('GET', 'POST', 'PUT'))
# def getObjectList():
#     if request.method == 'POST':
#         data = getList('3')
#         print('Received data')
#         return make_response(jsonify(data))

#     return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

# def getList(contenttype):
#     cons = db.session.query(Content.content_id,
#                                 Content.content_name,
#                                 Content.content_type,
#                                 Content.content_load_type,
#                                 Content.description,
#                                 Content.version).filter_by(build_target='Android',content_type=contenttype).all()

#     userCon = db.session.query(UserContents.content_id,
#                                 UserContents.content_name,
#                                 UserContents.content_type,
#                                 UserContents.content_load_type,
#                                 UserContents.description,
#                                 UserContents.version).filter_by(build_target='Android',content_type=contenttype).group_by('content_id').all()

#     print(userCon.__len__())
#     result = cons + userCon

#     if result is not None :
#         content_schema = UserContentsSchema()
#         data = content_schema.dump(result,many = True )
#         respData = {'contents' : data}
#         responseObject = {
#             'status': 'success',
#             'data': respData,
#             'message' : ''
#         }
#         return responseObject

# @mod_usercontents.route('/add', methods=('GET', 'POST', 'PUT'))
# def DynamicContent():
#     if request.method == 'POST':
#         try :
#             # cid = request.form['ContentID']
#             contentname = request.form['ContentName']
#             contenttype = request.form['ContentType']
#             # contentloadtype = request.form['ContentLoadType']
#             version = request.form['Version']
#             buildtarget = request.form['BuildTarget']
#             buildversion = request.form['BuildVersion']
#             polyVersion = request.form['PolyVersion']
#             f = request.files['file']
#             shaderFile = request.files['Shader']
#             hashFile = request.files['Hash']
#             jsonFile = request.files['Json']
#             # thumbf = request.files['thumbnailFile']
#             description= request.form['Description']
#             owner = request.form['Owner']
#             accesstype  = request.form['AccessType']

#         except Exception as e :
#             return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing Entry'}))

#         error = None
#         thumbnail_error = None
#         path = None

#         # if not cid :
#         #     error = 'Missing "ContentID"'
#         # else:
#         #     contentid = contentname+'_EXT'
#         if not contenttype:
#             error = 'Missing "ContentType"'
#         else:
#             if contenttype == "1":
#                contentloadtype = "1"
#             else:
#                 contentloadtype = "2"
#         # if not contentloadtype:
#         #     error = 'Missing "ContentLoadType"'
#         if not contentname:
#             error = 'Missing "ContentName"'
#         else:
#             contentid = contentname+'_EXT'
#         if not owner:
#             error = 'Missing "Owner"'
#         elif not accesstype :
#             error = 'Missing "AccessType"'
#         elif not version :
#             error = 'Missing "Version"'
#         elif not buildtarget :
#             error = 'Missing "BuildTarget"'
#         elif not buildversion:
#             error = 'Missing "BuildVersion"'
#         elif not polyVersion:
#             error = 'Missing "PolyVersion"'
#         elif not f :
#             error = 'Missing "file"'
#         elif not shaderFile :
#             error = 'Missing "ShaderFile"'
#         elif not hashFile :
#             error = 'Missing "HashFile"'
#         elif not jsonFile :
#             error = 'Missing "Jsonfile"'
#         print(contentid)
#         duplicates = UserContents.query.filter_by(content_id=contentid,content_name=contentname ,build_target=buildtarget).first()

#         if duplicates is not None :
#             error = 'Duplicate content'

#         duplicates = Content.query.filter_by(content_id=contentname,build_target=buildtarget).first()

#         if duplicates is not None :
#             error = 'Duplicate content'

#         if error is None:
#             try :
#                 print ('No errors... uploading file.')

#                 # dir_new = os.path.join(uploads_dir ,buildversion)
#                 # CreateDirectory(dir_new)

#                 # dir_new_buildtarget = os.path.join(dir_new ,buildtarget)
#                 # CreateDirectory(dir_new_buildtarget)

#                 # poly_path = os.path.join(dir_new_buildtarget ,polyVersion)
#                 # CreateDirectory(poly_path)

#                 # file_path = os.path.join(poly_path ,contentname)
#                 # CreateDirectory(file_path)

#                 content = UserContents()
#                 content.content_id = contentid
#                 content.content_name = contentname
#                 content.content_type = contenttype
#                 content.content_load_type = contentloadtype
#                 content.owner = owner
#                 content.access_type = accesstype
#                 content.build_target = buildtarget
#                 content.version = version
#                 content.thumbnail_path = app.config['UPLOAD_FOLDER']
#                 if description :
#                     content.description = description


#                 UploadFile(f,content,file_path)
#                 UploadFile(hashFile,content,file_path)
#                 UploadFile(jsonFile,content,file_path)
#                 UploadFile(shaderFile,content,file_path)


#                 print ('file uploaded successfully')

#                 print('Sucess')
#                 msg = 'Content data added sucessfully.'

#                 responseObject = {
#                         'status': 'success',
#                         'message': msg,
#                         'data' : ''
#                     }
#                 return make_response(jsonify(responseObject))

#             except Exception as e:
#                 print ('file upload fail  '+str(e))
#                 error = 'File upload failed. Change content ID'
#                 responseObject = {
#                 'status': 'fail',
#                 'message': error,
#                 'data' : ''
#             }

#             return make_response(jsonify(responseObject))


#         else:
#             print('sending fail status')
#             responseObject = {
#                 'status': 'fail',
#                 'message': error,
#                 'data' : ''
#             }

#             return make_response(jsonify(responseObject))

#     return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))
