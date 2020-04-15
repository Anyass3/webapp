import os
import secrets
from PIL import Image
from threading import Thread
from flask import url_for, current_app, render_template
#from hello import ShortenName
from webapp import mail
from flask_mail import Message


##################################picture#################################
def save_pic(form_pic,x,y):
    random_hex = secrets.token_hex(8)
    _, f_ext =os.path.splitext(form_pic.filename)
    pic_fn = random_hex + f_ext
    pic_path = os.path.join(current_app.root_path, 'static/img', pic_fn)

    output_size = (x, y)
    i = Image.open(form_pic)
    i.thumbnail(output_size)

    i.save(pic_path)

    return pic_fn


##################################email#################################
"""
def send_reset_email(user):
    token = user.generate_token()
    msg = Message('Password Reset Request', sender='nyassabu@gmail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
 {url_for('users.resetToken', token=token, _external=True)}

 If you did not make this request then simply ignore this email and no changes will be made

    '''
    mail.send(msg)
"""
def send_async_email(current_app, msg):
    with current_app.app_context():
        mail.send(msg)

def send_email(to, subject, templete, **kwargs):
    msg = Message(subject, sender='noreply@gmail.com', recipients=[to])
    msg.body = render_template(templete + '.txt', **kwargs)
    msg.html = render_template(templete + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[current_app,msg])
    thr.start()
    return thr
    #mail.send(msg)