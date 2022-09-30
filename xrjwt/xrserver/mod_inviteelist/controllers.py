import functools
#from datetime import time
from flask import jsonify, make_response
# from flask_httpauth import HTTPBasicAuth
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from xrserver import db
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
# Import module models
from .models import InviteeList
from ..mailsetup import email_send
from .schemas import InvieeListSchema
import time
import datetime
mod_invitee_list = Blueprint(
    'invitee_list', __name__, url_prefix='/inviteeList')


@mod_invitee_list.route('/inviteEmail', methods=('GET', 'POST', 'PUT'))
@jwt_required()
def inviteEmail():
    if request.method == "POST":
        starttime=time.time()
        idenetity=get_jwt_identity()
        try:
            emailList = list((request.form["email"]).split(","))
            sessionId = request.form['eventID']
            print(type(emailList), 'email', emailList)
        except Exception as e:
            return make_response(
                jsonify({"status": "fail", "message": str(e), "data": ""})
            )

        for email in emailList:
            email_send(email, 5)
            content = InviteeList()
            content.session_id = sessionId
            content.invitee_email = email
            content.invite_link = 'https://demo.xrconnect.com/web/login'

            db.session.add(content)
            db.session.commit()
            print(email)
            endtime=time.time()
            
        responseObject = {"status": "success",
                          "data": emailList,"eventID":sessionId, "message": "Invitation Sent Successfully",'Time taken':endtime -starttime}
        return make_response(jsonify(responseObject))

    return make_response(
        jsonify({"status": "fail", "message": "check method type.", "data": ""})
    )
