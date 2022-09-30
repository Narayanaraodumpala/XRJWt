# Import the database object (db) from the main application module
# We will define this inside /app/__init__.py in the next sections.
from xrserver import db
from xrserver import app
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from ..models import Base

# Define a User model/Database
class User(Base):
    __tablename__ = 'auth_user'

    email = db.Column(db.String(128), index=True, primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(64), nullable=True)
    last_name = db.Column(db.String(64), nullable=True)
    gender = db.Column(db.String(32), nullable=False)
    role = db.Column(db.String(10), index=True, nullable=False)
    date_of_birth = db.Column(db.DateTime, nullable=True)
    phone_number = db.Column(db.Integer, nullable=True)
    user_name = db.Column(db.String(32))
    token = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, unique=False, default=True)
    vrcode = db.Column(db.String(6), nullable=True)
    company_name = db.Column(db.String(150), index=True, nullable=False)
    system_ID = db.Column(db.String(256), nullable=True)
    login_status = db.Column(db.Boolean, nullable=True)
    image_path=db.Column(db.String(150),nullable = True)
    is_social_user= db.Column(db.Boolean,unique=False,default=False)
    provider=db.Column(db.String(30),nullable = True)

    # # New instance instantiation procedure
    # def __init__(self, email, password):

    # # self.name     = name
    # self.email    = email
    # self.password = password

    update_fields = ['email']

    def __repr__(self):
        return '<User %r>' % (self.email)

# Password Hashing
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

# Encode Token
    @staticmethod
    def verify_auth_token(token):
        try:
            payload = jwt.decode(auth_token, app.config['SECRET_KEY'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

# Decode Token
    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'
