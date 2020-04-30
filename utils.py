import os
import secrets
from PIL import Image
from threading import Thread
from flask import url_for, current_app, render_template
from webapp import create_app, mail
#
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
def send_async_email(msg):
    print("send_async_email")
    app = create_app()
    app.app_context().push()
    with app.app_context():
        print("mail.send")
        mail.send(msg)

def send_email(to, subject, templete, **kwargs):
    msg = Message(subject, sender='noreply@gmail.com', recipients=[to])
    try:
        msg.body = render_template(templete + '.txt', **kwargs)
    except:
        pass
    msg.html = render_template(templete + '.html', **kwargs)
    thr = Thread(target=send_async_email, args=[msg])
    print("thr")
    thr.start()
    print("thr.start()")
    return thr
    #mail.send(msg)