# Statement for enabling the development environment
DEBUG = True

# Define the application directory
import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# from xrserver.mod_auth.controllers import mod_auth as auth_module
# from flask import  Flask
# from flask_swagger_ui import get_swaggerui_blueprint
# #from routes import request_api
# from  .xrserver import mod_auth
# SWAGGER_URL = '/swagger'
# API_URL = '/static/swagger.json'
# SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
#     SWAGGER_URL,
#     API_URL,
#     config={
#         'app_name': "Seans-Python-Flask-REST-Boilerplate"
#     }
# )
#
# app = Flask(__name__, instance_relative_config=True)
# app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
# ### end swagger specific ###
#
#
# app.register_blueprint(auth_module.get_blueprint())
#




# Define the database - we are working with
# SQLite for this example
#SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:@localhost/xrconn_xrcoreflaskdb' #mysql://username:password@server/db 




#  db connection for xrconnect(B2C)

# mysql://username:password@server/db

# devhttp://165.232.176.109:8080/#/player/33
# SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://xrconnect_b2c_dev:Hyderabad1990@20.204.30.104/xrconnect_b2c_dev'

# qa
#SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://xrconnect_b2c_qa:Hyderabad1991@20.204.30.104/xrconnect_b2c_qa' #mysql://username:password@server/db

# prod
# SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://xrconnect_prod:Reinvision2021@20.204.30.104/xrconnect_prod' #mysql://username:password@server/db

#localhoat
# SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:@localhost/stage_servers' #mysql://username:password@server/db




#SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://serverdb:serverdb@192.168.0.109/stage_server_update' #mysql://username:password@server/db
SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://root:@localhost/stage_server_update' #mysql://username:password@server/db

SQLALCHEMY_ENGINE_OPTIONS = {
    'connect_args': {
        'connect_timeout': 10
    }
}

DATABASE_CONNECT_OPTIONS = {}
UPLOAD_FOLDER = "."
SQLALCHEMY_TRACK_MODIFICATIONS = False
# Application threads. A common general assumption is
# using 2 per available processor cores - to handle
# incoming requests using one and performing background
# operations using the other.
THREADS_PER_PAGE = 2

# Enable protection agains *Cross-site Request Forgery (CSRF)*
CSRF_ENABLED     = True

# Use a secure, unique and absolutely secret key for
# signing the data. 
CSRF_SESSION_KEY = "secret"

# Secret key for signing cookies
SECRET_KEY = "secret"