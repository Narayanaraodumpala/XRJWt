# from flask import Flask, jsonify, request
import smtplib  # Import smtplib for the actual sending function
from email.message import EmailMessage  # Import the email modules we'll need
from flask import Flask, request, url_for


def email_send(email, choice, firstname=None,token=None, sessionid=None):
    # email = request.form.get('email')
    # SMTP stuff
    print('sending mail to',email)
    s = smtplib.SMTP(host='smtp.gmail.com', port=587)
    print('sending...')
    s.starttls()
    # s.login('support@hudle.io', 'Rein1234#')
    s.login('support@xrconnect.io', 'support@!23')
    print('sending...after login....')

    # Email Notifications for each actions
    msg = EmailMessage()
    
    # Email Verification for first time user
    if choice == 1:
        print(' in choice 1')
        msg['Subject'] = 'Registration confirmation!'
        link = url_for('auth.confirm_email', token=token, _external=True)
        msg.set_content(
            f"""\
			<!DOCTYPE html>
			<html>
			<body>
			<h3>Click below to Verify Your Account</h3>
                <div style="width: 50%;text-align: center;"><a href="{link}"><button>Verify</button></a></div>
						</body>
						</html>""", subtype='html')
        print('email sent successfully')
    # Account activated after verifying email
    elif choice == 2:
        print(' in account confirmation')
        msg['Subject'] = 'Account Confirmation'
        msg.set_content(f'Hey! {email} is activated.')
    # Mail notification send to Host regarding new session 
    elif choice == 3:
        print(' in new session creation')
        msg['Subject'] = 'New session Created!'
        msg.set_content(
            f'This host {email} has created a session sucessfully.')
    # Mail notification send to Host regarding session Deleted
    elif choice == 4:
        print(' in session deleted')
        msg['Subject'] = 'Session Deleted!'
        msg.set_content(
            f'This host {email} has deleted a session sucessfully.')
    # Mail invitation to the event from Host to users 
    elif choice == 5:
        print(' in sending invitaion')
        # msg['Subject'] = 'You are invited to the Event {sessionid}!'
        # msg.set_content(f'session user {email} data added sucessfully')
        msg['Subject'] = 'Invitation mail'
        link = 'https://dev.hudle.io/#/login'
        msg.set_content(
            f"""\
			<!DOCTYPE html>
			<html>
			<body>
			<h3>Click below to join the event</h3>
			    <div style="width: 50%;text-align: center;"><a href="{link}"><button>Join Event</button></a></div>
            </body>
            </html>""", subtype='html'
        )
    # Password reset verification link
    elif choice == 7:
        print(' in password reset')
        msg['Subject'] = 'Password Reset'
        link = url_for('auth.reset_Password_verify',
                       token=token, _external=True)
        msg.set_content(
            f"""\
			<!DOCTYPE html>
			<html>
			<body>
			<h3>Click below to Verify Your Account</h3>
			    <div style="width: 50%;text-align: center;"><a href="{link}"><button>Verify</button></a></div>
            </body>
            </html>""", subtype='html'
        )
    # Password updated Mail notification
    elif choice == 9:
        print('in password updation')
        msg['Subject'] = 'Password updated!'
        msg.set_content(f'User {email} password updated.')
    # Mail Notification for VR device connected
    elif choice == 10:
        msg['Subject'] = 'VR device is connected!'
        msg.set_content(f'User {email} VR Connected.')
    # Confirmation mail for contact us form
    elif choice == 11:
        msg['Subject'] = 'Thanks for contacting us!'
        msg.set_content(f'Hi {firstname}, Thank you for getting in touch! We appreciate you contacting us. One of our member will be getting back to you shortly. Thanks in advance for your patience. Have a great day! Regards, XRConnect')
    elif choice == 12:
        msg['Subject'] = 'Hurray!'
        msg.set_content(f'Hi {email}, Thank you for your interest to Connect with us. We will be sending you the invitation shortly.')
    else:
        print(f'Please enter correct details')

    # the recipient's email address
    msg['From'] = 'XR Connect <support@xrconnect.io>'
    # msg['From']='Sunil Golla <support@hudle.io>'
    msg['To'] = f'{email}'  # the sender's email address

    s.send_message(msg)
    s.quit()
    return 'Email sent!'
