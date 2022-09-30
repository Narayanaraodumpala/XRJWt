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
import math
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# from sqlalchemy import Identity
#import psutil
from werkzeug.utils import secure_filename
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
import time

from xrserver import db,app


# Import module models
from .models import Content

from ..mod_usercontents.controllers import db as UserContentsDB
from ..mod_usercontents.models import UserContents

from .schemas import ContentSchema

mod_content = Blueprint('content', __name__, url_prefix='/contents')

uploads_dir = os.path.join(app.instance_path, 'Assets')

#app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
#  add Ambience and appication related to internal uploads
@mod_content.route('/add', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def content():
    if request.method == 'POST':
        starttime=time.time()
        idenetity=get_jwt_identity()
        try :
            contentid = request.form['ContentID']
            contenttype = request.form['ContentType']
            contentloadtype = request.form['ContentLoadType']
            description= request.form['Description']
            owner = request.form['Owner']
            accesstype  = request.form['AccessType']
            permittedusers = request.form['PermittedUsers']
            file_name = request.form['FileName']
            version = request.form['Version']
            buildtarget = request.form['BuildTarget']
            buildversion = request.form['BuildVersion']
            #polyVersion = request.form['PolyVersion']
            contentname = request.form['ContentName']
            f = request.files['file']
            # thumbf = request.files['thumbnailFile']
            # print('1')
                       
        except KeyError as e:
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : ''}))
        except IndexError as e:
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : ''}))    
        except Exception as e :
            return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : ''}))
            
        error = None
        thumbnail_error = None
        path = None
        
        if not contentid :
            error = 'Missing "ContentID"'
        if not contentname :
            error = 'Missing "ContentName"'
        if not contenttype:
            error = 'Missing "ContentType"'
        if not contentloadtype:
            error = 'Missing "ContentLoadType"'
        elif not owner:
            error = 'Missing "Owner"'
        elif not accesstype :
            error = 'Missing "AccessType"'
        elif not file_name :
            error = 'Missing "FileName"'
        elif not version :
            error = 'Missing "Version"'
        elif not buildtarget :
            error = 'Missing "BuildTarget"'
        elif not buildversion:
            error = 'Missing "BuildVersion"'
        elif not polyVersion:
            error = 'Missing "PolyVersion"'
        elif not f :
            error = 'Missing "file"'
        elif Content.query.filter_by(content_id=contentid, build_target=buildtarget).first() is not None : 
            error = 'Duplicate content'
        # elif Content.query.filter_by(content_type=contenttype,path = path).first() is not None :
            # error = 'Duplicate content'          
        elif f :
            try :
                print ('No errors... uploading file.')
                
                dir_new = os.path.join(uploads_dir ,buildversion) 
                if not os.path.exists(dir_new) :
                    print('Creating folder'+ dir_new)
                    os.mkdir(dir_new)

                dir_new_buildtarget = os.path.join(dir_new ,buildtarget) 
                if not os.path.exists(dir_new_buildtarget) :
                    print('Creating folder'+ dir_new_buildtarget)
                    #os.mkdirs(dir_new_buildtarget)
                    os.mkdir(dir_new_buildtarget)

                poly_path = os.path.join(dir_new_buildtarget ,polyVersion) 
                if not os.path.exists(poly_path) :
                    print('Creating folder'+ poly_path)
                    os.mkdir(poly_path)
                
                path = os.path.join(poly_path, secure_filename(f.filename))
                print('uploading  to ' + path)
                f.save(path)                
                print ('file uploaded successfully')
            except :
                print ('file upload fail')
                error = 'File upload failed.'
        elif thumbf :
            try : 
                print ('Uploading thumbnail.')
                thumbf.save(os.path.join(uploads_dir, secure_filename(file.name)))
                print ('thumbnail uploaded successfully')
            except :
                print ('thumbnail upload fail')
                thumbnail_error = 'Thumbnail upload failed.'

        if error is None:
            content = Content()
            content.content_id = contentid
            content.content_type = contenttype
            content.content_load_type = contentloadtype
            content.owner = owner 
            content.access_type = accesstype
            content.file_name = file_name
            content.build_target = buildtarget
            content.content_name = contentname
            if path :
                content.path = path
            content.version = version
            content.thumbnail_path = app.config['UPLOAD_FOLDER']
                
            if description :
                content.description = description
            if permittedusers :
                content.permitted_users = permittedusers               
           
            db.session.add(content)
            db.session.commit()
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            print('Sucess')
            msg = 'Content data added sucessfully.'
            if thumbnail_error : 
                msg = msg +" " +thumbnail_error
            endtime=time.time()
            responseObject = {
                    'status': 'success',
                    'message': msg,
                    'data' : '',
                    "Time taken":endtime  - starttime
                    
                }
            return make_response(jsonify(responseObject))
        
        else:
            print('sending fail status')
            endtime=time.time()
            responseObject = {
                'status': 'fail',
                'message': error,
                'data' : '',
                "Time taken":endtime  - starttime
            }    
        
            return make_response(jsonify(responseObject))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))



# @mod_content.route('/getContentData', methods=('GET', 'POST', 'PUT'))
# def getContent():
#     if request.method == 'POST':
#         try :
#             contentid = request.form['ContentID']
#         except Exception as e :
#             return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : ''}))

#         print(app.instance_path)
#         print('content request for ID '+contentid)
#         con = Content.query.filter_by(content_id=contentid).first()
        
#         error = None
#         if con is None :
#             error = 'No existing content'
#         elif error is None:
#             try:
#                 print('downloading file')
#                 responseObject = {
#                 'status': 'success',
#                 'message': '',
#                 'data' : con.file_name
#                 }
#                 print('data packed in json')

#                 resp = make_response(responseObject)
#                 print ('download successful')
#                 return resp

#             except Exception as e :
#                 print('exception '+ str(e))
#                 error = str(e)
#                 return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : ''}))
        
#         if error is not None:       
#             responseObject = {
#                 'status': 'fail',
#                 'message': error,
#                 'data' : ''
#             }            
#             return make_response(jsonify(responseObject))
            
#     return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))
    
@mod_content.route('/getContentData', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getContent():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']== 'SuperAdmin':
            try :
                contentid = request.form['ContentID']
                try:
                    buildTarget = request.form['BuildTarget']
                except:
                    print('form field not found')
            except Exception as e :
                return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : ''}))

            print(app.instance_path)
            print('content request for ID '+contentid)
            try:
                con = Content.query.filter_by(content_id=contentid,build_target=buildTarget).first()
            except:
                con = Content.query.filter_by(content_id=contentid).first()
            
            error = None
            # refresh = create_refresh_token(identity='user')
            # access = create_access_token(identity='user')
            if con is None :
                error = 'No existing content'
            
            elif error is None:
                try:
                    print('downloading file')
                    endtime=time.time()
                    responseObject = {
                    'status': 'success',
                    'message': '',
                    # 'access':access,
                    # 'refresh':refresh,
                    'data' : con.file_name,
                    'time taken':endtime - starttime
                    }
                    print('data packed in json')

                    resp = make_response(responseObject)
                    print ('download successful')
                    return resp

                except Exception as e :
                    print('exception '+ str(e))
                    error = str(e)
                    endtime=time.time()
                    return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : '','Time taken':endtime - starttime}))
            
            if error is not None:       
                endtime=time.time()
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data' : '',
                    'Time taken':endtime - starttime
                }            
                return make_response(jsonify(responseObject))
        else:
            endtime=time.time()
            return make_response(jsonify({'status' : 'fail', 'message' : "sorry, you don't have permissions",'data' : '',  'Time taken':endtime - starttime}))
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))
    
@mod_content.route('/getContentFile', methods=('POST', 'GET'))
@jwt_required()
def getContentFile():
    if request.method == 'POST': 
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']== 'SuperAdmin':
            try:
                contentid = request.form['ContentID']
                buildtarget = request.form['BuildTarget']
                buildversion = request.form['BuildVersion']
                polyVersion = request.form['PolyVersion']
            except Exception as e :
                return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : ''}))

            
            print('content request for ID '+contentid)
            print(buildtarget)        
            con = Content.query.filter_by(content_id=contentid, build_target=buildtarget).first()
            
            error = None
            
            if con is None :
                error = 'No existing content'
        
            else:
                try:
                    path = os.path.join(uploads_dir,buildversion,buildtarget,polyVersion,con.file_name)
                    print('downloading file ' + path)
                    rv = send_file(path)
                    rv.direct_passthrough = False
                    print('received file from server')
                    return rv
                
                except Exception as e :
                    endtime=time.time()
                    print('exception '+ str(e))
                    error = str(e)
                    return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : '','Time taken':endtime - starttime}))

            if error is not None:    
                endtime=time.time()   
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data' : '',
                    'time taken':endtime - starttime
                }            
                return make_response(jsonify(responseObject))
        else:
            return make_response(jsonify({'status' : 'fail', 'message' : "sorry, you don't have permissions",'data' : ''}))
     
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))   

# get ambience list - envi ID
@mod_content.route('/getEnvList', methods=['GET'])
@jwt_required()
def getEnvList():
    if request.method == 'GET':
        identity=get_jwt_identity()
        data = getList('1')
        print('Received data')
        return make_response(jsonify(data))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

# get ambience list with respective pagination - envi ID
@mod_content.route('/getEnvpaginationlist',methods=['GET'])
@jwt_required()
def getEnvpagination():
    if request.method == 'GET':
        identity=get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('size', 5, type=int)
        content_name = request.args.get('content_name', '', type=str)
        data = getListPaginate('1',content_name,page,per_page)
        print('Received data')
        return make_response(jsonify(data))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))
    

# get application list - app ID
@mod_content.route('/getAppList', methods=['GET'])
@jwt_required()
def getAppList():
    if request.method == 'GET': 
        Identity=get_jwt_identity()       
        data = getList('2')
        print('Received data')
        return make_response(jsonify(data))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


# get application list with respective pagination - envi ID
@mod_content.route('/getApppaginationlist',methods=['GET'])
@jwt_required()
def getApppagination():
    if request.method == 'GET':
        identity=get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('size', 5, type=int)
        content_name = request.args.get('content_name', '', type=str)
        data = getListPaginate('2',content_name,page,per_page)
        print('Received data')
        return make_response(jsonify(data))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


# get tools list - tools ID
# @mod_content.route('/getToolsList', methods=('GET', 'POST', 'PUT'))
# def getAppList():
#     if request.method == 'GET':
#         data = getList('3')
#         print('Received data')
#         return make_response(jsonify(data))
        
#     return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))


@mod_content.route('/getCatalogList', methods=['GET'])
@jwt_required()
def getCatalogList():
    starttime=time.time()
    identity=get_jwt_identity()
    if identity['role']== 'SuperAdmin':
        if request.method == 'GET':
            data = getList('0')
            print('Received data')
            return make_response(jsonify(data))
    else:
         
         return make_response(jsonify({'status' : 'fail', 'message' : "sorry, you don't have permissions",'data' : ''}))
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))        

def getListPaginate(contenttype,content_name,page,per_page):
    starttime=time.time()
    cons = db.session.query(Content.content_id,
                                Content.content_name,
                                Content.content_type,
                                Content.content_load_type,
                                Content.description,
                                Content.version,Content.file_name).filter_by(content_type=contenttype).group_by('content_id')
    if content_name is not None:
        content_name = "%{}%".format(content_name)
        cons=cons.filter(Content.content_name.like(content_name))

    userCon = db.session.query(UserContents.content_id,
                                UserContents.content_name,
                                UserContents.content_type,
                                UserContents.content_load_type,
                                UserContents.description,
                                UserContents.version,UserContents.file_name).filter_by(content_type=contenttype).group_by('content_id')
    if content_name is not None:
        content_name = "%{}%".format(content_name)
        userCon=userCon.filter(UserContents.content_name.like(content_name))

    offset=(page-1)*per_page
    result2=cons.union_all(userCon)
    result=cons.union_all(userCon).limit(per_page).offset(offset)
    total=0
    if result2 is not None :
        content_schema = ContentSchema()
        data2 = content_schema.dump(result2,many = True )
        total=len(data2)


    #result = cons + userCon
    # result = userCon
    if result is not None :
        content_schema = ContentSchema()
        data = content_schema.dump(result,many = True )
        respData = {'contents' : data}
        endtime=time.time()
        responseObject = {
            'status': 'success',    
            'data': respData,
            'totalItems': total,
            'totalPages':math.ceil(total/per_page),
            'currentPage':page,
            'message' : ''    ,
            "Time taken":endtime - starttime            
        }  
        return responseObject

def getList(contenttype):
    starttime=time.time()
    cons = db.session.query(Content.content_id,
                                Content.content_name,
                                Content.content_type,
                                Content.content_load_type,
                                Content.description,
                                Content.version,Content.file_name).filter_by(content_type=contenttype).group_by('content_id')
    
    userCon = UserContentsDB.session.query(UserContents.content_id,
                                UserContents.content_name,
                                UserContents.content_type,
                                UserContents.content_load_type,
                                UserContents.description,
                                UserContents.version,UserContents.file_name).filter_by(content_type=contenttype).group_by('content_id')
        
    result=cons.union_all(userCon)
    #print(userCon.__len__())
    #result = cons + userCon
    # result = userCon
    
    if result is not None :
        content_schema = ContentSchema()
        data = content_schema.dump(result,many = True )
        respData = {'contents' : data}
        endtime=time.time()
        responseObject = {
            'status': 'success',    
            'data': respData,
            'message' : ''     ,
            'Time taken':endtime - starttime
                  
        }  
        return responseObject

@mod_content.route('/getCatalogFiles', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def getCatalogFile():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']== 'SuperAdmin':
            try :
                contentid = request.form['ContentID']
                buildtarget = request.form['BuildTarget']

            except Exception as e :
                return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : 'Missing form data'}))

            print(buildtarget)  
            print(contentid)      
            con = Content.query.filter_by(content_id=contentid, build_target=buildtarget).first()
            
            error = None
            
            if con is None :
                error = 'No existing content'
            else:
                try:
                    print('downloading file')
                    rv = send_file(con.path)
                    rv.direct_passthrough = False
                    print('received file from server')
                    #return rv
                    # byte = base64.b64encode(rv.data)
                    byte = base64.b64encode(rv.data)
                    #print(byte)
                    print('converted to bytes')
                    dataStr = {'content_type' : con.content_type, 'fileName':con.file_name, 'file':str(byte)}
                    
                    endttime=time.time()
                    responseObject = {
                    'status': 'success',
                    'message': '',
                    'data' : dataStr,
                    'Time taken':endttime - starttime,
                
                    }
                    print('data packed in json')

                    resp = make_response(responseObject)
                    print ('download successful')
                    return resp
                
                except Exception as e :
                    print('exception '+ str(e))
                    error = str(e)
                    return make_response(jsonify({'status' : 'fail', 'message' : str(e),'data' : ''}))

            if error is not None:       
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data' : ''
                }            
                return make_response(jsonify(responseObject))
        else:
            
         return make_response(jsonify({'status' : 'fail', 'message' : "sorry, you don't have permissions",'data' : ''}))
     
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))



@mod_content.route('/getToolsList', methods=['GET'])
@jwt_required()
def getToolsList():
    if request.method == 'GET':
            
            identity=get_jwt_identity()
            if identity['role']== 'SuperAdmin':
                data = getList1('3')
                print('Received data')
                return make_response(jsonify(data))
            else:
            
             return make_response(jsonify({'status' : 'fail', 'message' : "sorry, you don't have permissions",'data' : ''}))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))        

def getList1(contenttype):
    starttime=time.time()
    cons = db.session.query(Content.content_id,
                                Content.content_name,
                                Content.content_type,
                                Content.content_load_type,
                                Content.description,
                                Content.version).filter_by(build_target='Android',content_type=contenttype).all()
    
    userCon = db.session.query(UserContents.content_id,
                                UserContents.content_name,
                                UserContents.content_type,
                                UserContents.content_load_type,
                                UserContents.description,
                                UserContents.version).filter_by(build_target='Android',content_type=contenttype).group_by('content_id').all()
        
    print(userCon.__len__())
    result = cons + userCon
    
    if result is not None :
        content_schema = ContentSchema()
        data = content_schema.dump(result,many = True )
        respData = {'contents' : data}
        endttime=time.time()
        responseObject = {
            'status': 'success',    
            'data': respData,
            'message' : ''  ,
            'Time taken':endttime - starttime
                
        }  
        return responseObject  
    

#  add Ambience and appication related to internal uploads
@mod_content.route('/addAddressableInternal', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def azurecontent():
    if request.method == 'POST':
        starttime=time.time()
        identity=get_jwt_identity()
        if identity['role']== 'SuperAdmin':
            try :
                contentid = request.form['ContentID']
                contentname = request.form['ContentName']
                contenttype = request.form['ContentType']
                description= request.form['Description']
                owner = request.form['Owner']
                accesstype  = request.form['AccessType']
                version = request.form['Version']
                buildtarget = request.form['Platform']
                buildversion = request.form['BuildVersion']
                polyVersion = request.form['PolyVersion']
                uploadedBy = request.form['uploadedBy']
                
                f = request.form['file']
                # thumbf = request.files['thumbnailFile']
                        
            except KeyError as e:
                return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : ''}))
            except IndexError as e:
                return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : ''}))    
            except Exception as e :
                return make_response(jsonify({'status' : 'fail', 'message' : str(e), 'data' : ''}))
                
            error = None
            # thumbnail_error = None
            
            if not contentid :
                error = 'Missing "ContentID"'
            if not contentname :
                error = 'Missing "ContentName"'
            if not contenttype:
                error = 'Missing "ContentType"'
            else:
                if contenttype == "1":
                 contentloadtype = "1"
                else:
                    contentloadtype = "2"
            if not f :
                error = 'Missing "file"'
            else:
                # fn = str(f).rpartition('%2F')
                # file_name = str(fn[-1])
                file_name = str(f).rpartition('/')[-1]
                
            if not owner:
                error = 'Missing "Owner"'
            elif not accesstype :
                error = 'Missing "AccessType"'
            elif not version :
                error = 'Missing "Version"'
            elif not buildtarget :
                error = 'Missing "BuildTarget"'
                
            elif not uploadedBy :
                error = 'Missing "uploadedBy"'
            internalDuplicates = Content.query.filter_by(content_id=contentid, build_target=buildtarget).first()
            if internalDuplicates:
                error = 'Duplicate Addressable'
                print('duplicate record', internalDuplicates)
                db.session.delete(internalDuplicates)
                db.session.commit()
                error = None
                
            # elif Content.query.filter_by(content_id=contentid, build_target=buildtarget).first() is not None : 
            
            
            if error is None:
                content = Content()
                content.content_id = contentid
                content.content_type = contenttype
                content.content_load_type = contentloadtype
                content.owner = owner 
                content.access_type = accesstype
                content.file_name = file_name
                content.build_target = buildtarget
                content.content_name = contentname
                content.version = version
                content.path = f
                content.description = description
                content.uploaded_by = uploadedBy
                
                db.session.add(content)
                db.session.commit()
                # refresh = create_refresh_token(identity='user')
                # access = create_access_token(identity='user')
                
                msg = 'Content data added sucessfully.'
                endtime=time.time()
                responseObject = {
                        'status': 'success',
                        'message': msg,
                        'data' : '',
                        # 'refresh':refresh,
                        # 'access':access,
                        'Time taken':endtime - starttime
                    }
                return make_response(jsonify(responseObject))
            
            else:
                print('sending fail status')
                endtime=time.time()
                responseObject = {
                    'status': 'fail',
                    'message': error,
                    'data' : '',
                    'Time taken':endtime - starttime
                }    
            
                return make_response(jsonify(responseObject))
        else:
            
             return make_response(jsonify({'status' : 'fail', 'message' : "sorry, you don't have permissions",'data' : ''}))
        
    return make_response(jsonify({'status':'fail', 'message' : 'check method type.','data': ''}))

