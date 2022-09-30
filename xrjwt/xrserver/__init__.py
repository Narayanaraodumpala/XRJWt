import os
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask import Flask
from flasgger import  Swagger,swag_from
# Import SQLAlchemy
# from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from swagger import template,swagger_config
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from flask_swagger_ui import get_swaggerui_blueprint
class SQLAlchemy(_BaseSQLAlchemy):
    def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True
        
from flask_jwt_extended import JWTManager    
app = Flask(__name__, instance_relative_config=True)

# def create_app(test_config=None):
# create and configure the app

'''
code for jwt code by narayanarao dumpala



# from flask_jwt_extended import create_access_token
# from flask_jwt_extended import get_jwt
# from flask_jwt_extended import get_jwt_identity
# from flask_jwt_extended import jwt_required
# from flask_jwt_extended import JWTManager
# from flask_jwt_extended import set_access_cookies
# from flask_jwt_extended import unset_jwt_cookies


# app.config["JWT_COOKIE_SECURE"] = True
# app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
# app.config["JWT_SECRET_KEY"] = "secret"  # Change this in your code!
# app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
# app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
# app.config['JWT_REFRESH_COOKIE_PATH'] = '/auth/refresh_token'
# app.config['JWT_COOKIE_CSRF_PROTECT'] = True
# app.config['JWT_COOKIE_SECURE'] = True
# app.config['JWT_CSRF_CHECK_FORM'] = True

# jwt = JWTManager(app)



'''

# from flask_restplus import Api,Resource,fields

# authorizations={
#     'apikey':{
#         'type':'apikey',
#         'in':'header',
#         'name':'X-API-KEY'
#     }
# }

# api=Api(app,authorizations=authorizations)
# from functools import wraps 


# def token_required(f,request):
#     @wraps(f)
#     def decorated(*args, **kwargs):

#         token = None

#         if 'X-API-KEY' in request.headers:
#             token = request.headers['X-API-KEY']

#         if not token:
#             return {'message' : 'Token is missing.'}, 401

#         if token != 'mytoken':
#             return {'message' : 'Your token is wrong, wrong, wrong!!!'}, 401

#         print('TOKEN: {}'.format(token))
#         return f(*args, **kwargs)

#     return decorated


''' 
creating a function to access the
JWT_ACCESS_TOKEN_EXPIRES,SECRET_KEY,SQLALCHEMY_DB_URI and JWT_SECRET_KEY and 
config the app to access the jwt key and register the app with JWTManager

'''

def create_app(test_config=None):
    
    app = Flask(__name__, instance_relative_config=True)
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=5)
    

    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DB_URI"),
           
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY'),


           
        )
    else:
        app.config.from_mapping(test_config)

JWTManager(app)

from flask_cors import CORS
CORS(app)
# from flask_cors import CORS
# # cors=CORS(app)
# cors = CORS(app, resources={r"/*": {"origins": "*"}}) # enabling CORS

app.config.from_object('config')


# flask swagger configs and access the swagger urkl with API_URL and register the blueprint off swagger
SWAGGER_URL = ''
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "XR Connect APIs"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

#app.config['SQLALCHEMY_ECHO'] = True
#print(app.config['SQLALCHEMY_DATABASE_URI'])

db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)

# Import a module / component using its blueprint handler variable (mod_auth)
from .mod_auth.controllers import mod_auth as auth_module
app.register_blueprint(auth_module)

from .mod_contact.controllers import mod_contact as contact_module
app.register_blueprint(contact_module)

from .mod_oculus.controllers import mod_oculus as oculus_module
app.register_blueprint(oculus_module)

from .mod_companyinfo.controllers import mod_compinfo as compinfo_module
app.register_blueprint(compinfo_module)

from .mod_auth.controllers import mod_user as user_module
app.register_blueprint(user_module)

from .mod_contents.controllers import mod_content as content_module
app.register_blueprint(content_module)

from .mod_sessions.controllers import mod_sessions as sessions_module
app.register_blueprint(sessions_module)

from .mod_event.controllers import mod_event as event_module
app.register_blueprint(event_module)

from .mod_permittedusers.controllers import mod_permitted_users as permitted_users_module
app.register_blueprint(permitted_users_module)

from .mod_sessionusers.controllers import mod_session_users as session_users_module
app.register_blueprint(session_users_module)

from .mod_media.controllers import mod_media as media_module
app.register_blueprint(media_module)

from .mod_sessionmedia.controllers import mod_session_media as session_media_module
app.register_blueprint(session_media_module)

from .mod_useravatars.controllers import mod_useravatars as user_avatars_module
app.register_blueprint(user_avatars_module)

from .mod_usercontents.controllers import mod_usercontents as user_content_module
app.register_blueprint(user_content_module)

from .mod_inviteelist.controllers import mod_invitee_list as invitee_list_module
app.register_blueprint(invitee_list_module)

from .mod_content_access.controllers import mod_content_access as content_access_module
app.register_blueprint(content_access_module)

from .mod_aviation.controllers import mod_add_aviation_api as mod_aviation_api
app.register_blueprint(mod_aviation_api)

#db.create_all()
