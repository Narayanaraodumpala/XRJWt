import functools
import imp
#from datetime import time
from flask import jsonify, make_response
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from xrserver import db
import time
import datetime
# Import module models
from .models import contentAccess
# from ..mailsetup import email_send
from .schemas import contentAccessSchema

mod_content_access = Blueprint(
    'content_access', __name__, url_prefix='/contentAccess')


@mod_content_access.route('/contentInvite', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def contentInvite():
    if request.method == "POST":
        starttime=time.time()
        idenetity=get_jwt_identity()
        try:
            emailList = list((request.form["email"]).split(","))
            contentId = request.form['contentId']
            
            print(type(emailList), 'email', emailList)
        except Exception as e:
            endtime=time.time()
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": "","Time taken":endtime - starttime})
            )

        for email in emailList:
            # email_send(email, 5)
            content = contentAccess()
            content.content_id = contentId
            content.invitee_email = email

            db.session.add(content)
            db.session.commit()
            print(email)
            endtime=time.time()
        responseObject = {"status": "success",
                          "data": emailList,"contentId":contentId, "message": "","Time taken":endtime - starttime}
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )
