from flask import Flask, render_template, url_for, flash, redirect, request, Blueprint, abort
#from hello import ShortenName
from webapp import db, bcrypt, login_manager
from webapp.users.forms import AssociationForm, ScholarForm, IndividualForm ,LoginForm, UpdateAssociationForm, UpdateScholarForm, UpdateIndividualForm, RequestResetForm, ResetPasswordForm, ChangePasswordForm, ChangeEmailForm
from webapp.models import User, Role, Post, Temp_user, Permission
from flask_login import login_user, current_user, logout_user, login_required
from webapp.utils import save_pic, send_email
from webapp.decorators import role_required
from flask_admin.helpers import is_safe_url
from datetime import datetime

users = Blueprint('users', __name__)


@users.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)


@users.before_app_request
def before_request():
    temp = Temp_user.query.all()
    for user in temp:
        user.ping()
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.active:
            logout_user()
            flash('Sorry!!!.Your account has been deactivated due to some issues', 'danger')
            flash('Please contact admin. For more info', 'info')
            return redirect(url_for('main.home'))
        
        if current_user.has_role('Individual') \
                and not current_user.confirmed \
                and request.blueprint != 'users' \
                and request.endpoint != 'static':
            return redirect(url_for('users.unconfirmed'))


#########################################register scetion Starts###################################
@users.route('/register', methods=['POST','GET'])
@users.route('/register#association', methods=['POST','GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = AssociationForm()
    if form.validate_on_submit():
        username=str(form.email.data).split('@')[0]
        u = User.query.filter_by(username=username).first()
        if u:
            username += '@' + str(form.shorten.data)
        temp = Temp_user.query.filter_by(temail=form.email.data).first()
        if temp and temp.trole == 'Association' and temp.code == form.code.data:
            pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(or_name=form.or_name.data, shorten=form.shorten.data,\
                    email=form.email.data, username=str(form.email.data).split('@')[0], password=pw_hash)
            Association = Role.query.filter_by(name='Association').first()
            user.role = Association
            db.session.add(user)
            db.session.delete(temp)
            db.session.commit()
            if current_user.is_authenticated:
                flash(f'Your account has been created. You are now automatically logged in', 'success')
                return redirect(url_for('main.home'))
            flash(f'Your account has been created. You may now log in here', 'success')
            return redirect(url_for('users.login'))
        else:
            if temp:
                temp.add_used()
                temp.delete()
            flash(f'You do not have a valid code or your email does not match with the code.', 'danger')
            return redirect(url_for('users.register'))
   
    return render_template('register/register#association.html', title='Register', form=form, active_register='active', active_A='active')

#TODO: add DOB
@users.route('/register#individual', methods=['POST','GET'])
def registerIndividual():
    form = IndividualForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    if form.validate_on_submit():
        username=str(form.email.data).split('@')[0]
        u = User.query.filter_by(username=username).first()
        if u:
            username +=  str(form.phone.data)
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(f_name=form.f_name.data, address=form.address.data, l_name=form.l_name.data, phone=form.phone.data, email=form.email.data, username=username, password=pw_hash)
        #Individual = Role.query.filter_by(name='Individual').first()
        #user.role = Individual
        db.session.add(user)
        db.session.commit()
        token = user.generate_token()
        send_email(user.email, 'confirm your account', 'email/send', user=user, token=token)
        if current_user.is_authenticated:
            flash(f'Your account has been created. You are now automatically logged in', 'success')
            return redirect(url_for('main.home'))
        flash(f'Your account has been created. You may now log in here', 'success')
        return redirect(url_for('users.login'))
   
    return render_template('register/register#individual.html', title='Register', form=form, active_register='active', active_I='active')

@users.route('/register#scholar', methods=['POST','GET'])
def registerScholar():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = ScholarForm()
    if form.validate_on_submit():
        username=str(form.email.data).split('@')[0]
        u = User.query.filter_by(username=username).first()
        if u:
            username +=  str(form.phone.data)
        temp = Temp_user.query.filter_by(temail=form.email.data).first()
        if temp and temp.trole == 'Scholar' and temp.code == form.code.data:
            pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(f_name=form.f_name.data, address=form.address.data, l_name=form.l_name.data, phone=form.phone.data, email=form.email.data, username=str(form.email.data).split('@')[0], password=pw_hash)
            Scholar = Role.query.filter_by(name='Scholar').first()
            user.role = Scholar
            db.session.add(user)
            db.session.delete(temp)
            db.session.commit()
            if current_user.is_authenticated:
                flash(f'Your account has been created. You are now automatically logged in', 'success')
                return redirect(url_for('users.loginScholar'))
            flash(f'Your account has been created. You may now log in here', 'success')
            return redirect(url_for('users.loginScholar'))
        else:
            if temp:
                temp.add_used()
                temp.delete()
            flash(f'You do not have a valid code or your email does not match with the code.', 'danger')
            return redirect(url_for('users.registerScholar'))
   
    return render_template('register/register#scholar.html', title='Register', form=form, active_register='active', active_S='active')
#########################################register section###################################




##########################################login section starts######################################
#TODO A UNIVERSAL LOGIN SYSYTEM
@users.route('/login', methods=['POST','GET'])
@users.route('/login/association', methods=['POST','GET'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    if form.validate_on_submit():
        # this will store the email of the user logging in
        #userloading = user_loading(email=form.email.data)
        #db.session.add(userloading)
        #db.session.commit()
        ########################################################
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            #anjloader = Association
            if not user.active:
                flash('Sorry you cannot login. Your account is deactivated due to some issues', 'danger')
                flash('Please contact admin', 'info')
                return redirect(url_for('main.home'))
            if user.has_role('Association'):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')

                #if not is_safe_url(next):
                #    abort(403)

                flash(f'Login successful. Welcome back {user.or_name}!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('main.home'))
            else:            
                if user.has_role('Scholar'):
                    flash('Login Unsuccessful. This is a scholar acoount. Please login here instead', 'info')
                    return redirect(url_for('users.loginScholar'))
                elif user.has_role('Individual'):
                    flash('Login Unsuccessful. This is a user acoount. Please login here instead', 'info')
                    return redirect(url_for('users.loginIndividual'))
                elif user.has_role('admin'):
                    flash('Login Unsuccessful. Please check email and password', 'danger')
                    return redirect(url_for('users.login'))

        else:
            #userloading.query.filter_by(email=form.email.data).delete()
            #db.session.commit()
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login/login#association.html', title='Login', signup='users.register', form=form, active_login='active', active_A='active')

@users.route('/login/scholar', methods=['POST','GET'])
def loginScholar():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # this will store the email of the user logging in
            #userloading = user_loading(email='scholar')
            #db.session.add(userloading)
            #db.session.commit()
            #anjloader = Scholar
            if not user.active:
                flash('Sorry you cannot login. Your account is deactivated due to some issues', 'danger')
                flash('Please contact admin', 'info')
                return redirect(url_for('main.home'))

            if user.has_role('Scholar'):
                login_user(user, remember=form.remember.data)
                #_del = user_loading.query.get(1)
                #db.session.delete(_del)
                #db.session.commit()
                next_page = request.args.get('next')

                #if not is_safe_url(next):
                #    abort(403)

                flash(f'Login successful. Welcome back {user.username}!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('main.home'))
            else:            
                if user.has_role('Association'):
                    flash('Login Unsuccessful. This is an association acoount. Please login here instead', 'info')
                    return redirect(url_for('users.login'))
                elif user.has_role('Individual'):
                    flash('Login Unsuccessful. This is a user acoount. Please login here instead', 'info')
                    return redirect(url_for('users.loginIndividual'))
                elif user.has_role('admin'):
                    flash('Login Unsuccessful. Please check email and password', 'danger')
                    return redirect(url_for('users.loginScholar'))

        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login/login#scholar.html', title='Login', signup='users.registerScholar', form=form, active_login='active', active_S='active')

@users.route('/login/individual', methods=['POST','GET'])
def loginIndividual():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.active:
                flash('Sorry you cannot login. Your account is deactivated due to some issues', 'danger')
                flash('Please contact admin', 'info')
                return redirect(url_for('main.home'))
            if user.has_role('Individual'):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')

                #if not is_safe_url(next):
                #    abort(403)

                flash(f'Login successful. Welcome back {user.email}!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('main.home'))
            else:            
                if user.has_role('Scholar'):
                    flash('Login Unsuccessful. This is a scholar acoount. Please login here instead', 'info')
                    return redirect(url_for('users.loginScholar'))
                elif user.has_role('Association'):
                    flash('Login Unsuccessful. This is an association acoount. Please login here instead', 'info')
                    return redirect(url_for('users.login'))
                elif user.has_role('admin'):
                    flash('Login Unsuccessful. Please check email and password', 'danger')
                    return redirect(url_for('users.loginIndividual'))

        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login/login#individual.html', title='Login', signup='users.registerIndividual', form=form, active_login='active', active_I='active')
#########################################LOGINS###################################





##################################LOGOUT#################################
@users.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))
##################################LOGOUT#################################




##################################ACCOUNTS#################################
@users.route('/account', methods=['POST','GET'])
@login_required
def account():
    if current_user.has_role('Scholar'):
        return redirect(url_for('users.accountScholar'))
    elif current_user.has_role('Individual'):
        return redirect(url_for('users.accountIndividual'))
    elif current_user.has_role('admin'):
        return redirect(url_for('myadmin.account'))
    form = UpdateAssociationForm()
    if form.validate_on_submit():
        if form.pic.data:
            pic_file = save_pic(form.pic.data,300,300)
            current_user.image_file = pic_file
        current_user.or_name = form.or_name.data
        current_user.shorten = form.shorten.data
        current_user.or_name = form.or_name.data
        current_user.username = form.username.data
        db.session.commit()
        #send email
        flash(f'Your account has been updated!', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.or_name.data = current_user.or_name
        form.shorten.data = current_user.shorten
        form.username.data = current_user.username
    image_file = url_for('static', filename='img/' + current_user.image_file)
    return render_template('account/account#association.html', title='account', ac_view='users.account', active_account='active', image_file = image_file, form=form)

@users.route('/accountscholar', methods=['POST','GET'])
@login_required
def accountScholar():
    if current_user.has_role('Association'):
        return redirect(url_for('users.account'))
    elif current_user.has_role('Individual'):
        return redirect(url_for('users.accountIndividual'))
    elif current_user.has_role('admin'):
        return redirect(url_for('myadmin.account'))
    form = UpdateScholarForm()
    if form.validate_on_submit():
        if form.pic.data:
            pic_file = save_pic(form.pic.data,300,300)
            current_user.image_file = pic_file
        current_user.f_name = form.f_name.data
        current_user.l_name = form.l_name.data
        current_user.address = form.address.data
        current_user.phone = form.phone.data
        current_user.username = form.username.data
        db.session.commit()
        #send email
        flash(f'Your account has been updated!', 'success')
        return redirect(url_for('users.accountScholar'))
    elif request.method == 'GET':
        form.f_name.data = current_user.f_name
        form.l_name.data = current_user.l_name
        form.address.data = current_user.address
        form.phone.data = current_user.phone
        form.username.data = current_user.username
    image_file = url_for('static', filename='img/' + current_user.image_file)
    return render_template('account/account#scholar.html', title='account', ac_view='users.accountScholar', active_account='active', image_file = image_file, form=form)

@users.route('/accountindividual', methods=['POST','GET'])
@login_required
def accountIndividual():
    if current_user.has_role('Scholar'):
        return redirect(url_for('users.accountScholar'))
    elif current_user.has_role('Association'):
        return redirect(url_for('users.account'))
    elif current_user.has_role('admin'):
        return redirect(url_for('myadmin.account'))
    form = UpdateIndividualForm()
    if form.validate_on_submit():
        if form.pic.data:
            pic_file = save_pic(form.pic.data,300,300)
            current_user.image_file = pic_file
        current_user.associationf_name = form.f_name.data
        current_user.l_name = form.l_name.data
        current_user.address = form.address.data
        current_user.phone = form.phone.data
        current_user.username = form.username.data
        db.session.commit()
        #send email
        flash(f'Your account has been updated!', 'success')
        return redirect(url_for('users.accountIndividual'))
    elif request.method == 'GET':
        form.f_name.data = current_user.f_name
        form.l_name.data = current_user.l_name
        form.address.data = current_user.address
        form.phone.data = current_user.phone
        form.username.data = current_user.username
    image_file = url_for('static', filename='img/' + current_user.image_file)
    return render_template('account/account#individual.html', title='account', ac_view='users.accountIndividual', active_account='active', image_file = image_file, form=form)
"""
@users.route('/account/individual/edit', methods=['POST','GET'])
@login_required
def edit_individual:
""" 
##################################ACCOUNTS#################################


#############################################CONFIRMATIONS#############################################
@users.route('/confirm/<token>')
@login_required
@role_required('Individual')
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.home'))
    if current_user.confirm(token):
        current_user.confirmed_at = datetime.utcnow()
        db.session.commit()
        flash('You have confirmed your account. Thanks', 'success')
    else:
        flash('The confirmation link is invalid or has expired')
    return redirect(url_for('main.home'))


@users.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.home'))
    return render_template('main/unconfirmed.html')

@users.route('/confirm/new')
@login_required
def new_confirm():
    token = current_user.generate_token()
    send_email(current_user.email, 'confirm your account', 'email/send', user=current_user, token=token, do='confirm', what='account')
    flash('A new confirmation email has been sent to you by email.', 'success')
    return redirect(url_for('main.home'))
#############################################CONFIRMATIONS#############################################


##################################Change and Reset#################################
@users.route('/change_password', methods=['POST','GET'])
@login_required
def change_pwd():
    form=ChangePasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            pw_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            current_user.password=pw_hash
            db.session.commit()
            #todo: send_email
            flash('You have changed password successfully', 'success')
            return redirect(url_for('users.account')) 
        else:
            flash("Current password is incorrect. Please try again.", 'danger' )
            #TODO: db to check the number of trials
            flash("If you forget password please logout if you still have access to your email to reset your password instead", 'info')
            return redirect(url_for('users.change_pwd'))
    return render_template('reset/change_pwd.html', form=form)

@users.route('/change_email', methods=['POST','GET'])
@login_required
def request_change_email():
    #TODO: email color > #500050
    token = current_user.generate_token()
    send_email(current_user.email, 'Change Email', 'email/send', user=current_user, token=token, do='change', what='email')
    flash('Success! Please check your email to continue.', 'success')
    return redirect(url_for('users.account'))
        
@users.route('/email/change_email/<token>', methods=['POST','GET'])
@login_required
def change_email(token):
    user = current_user.verify_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('users.account'))
    form=ChangeEmailForm()
    if form.validate_on_submit():
        current_user.email=form.email.data
        db.session.commit()
        flash('Success! Email changed', 'success')
        return redirect(url_for("users.account"))
    return render_template('reset/change_email.html', form=form, heading='Change Your Email')
        

@users.route('/reset_password', methods=['POST','GET'])
def resetRequest():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user.has_role('admin'):
            abort(403)
        token = user.generate_token()
        info = 'If you did not make this request then simply ignore this email and no changes will be made'
        send_email(user.email, 'Reset Password', 'email/send', user=user, info=info, token=token, do='reset', what='password')
        flash('An email has been sent with intsructions to reset your password', 'success')
        if user.has_role('Scholar'):
            return redirect(url_for('users.loginScholar'))
        elif user.has_role('Association'):
            return redirect(url_for('users.login'))
        elif user.has_role('Individual'):
            return redirect(url_for('users.loginIndividual'))
        else:
            return redirect(url_for('main.home'))
    return render_template('reset/reset_request.html', title='Reset Password', form=form)

@users.route('/reset_password/<token>', methods=['POST','GET'])
def resetToken(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('users.resetRequest'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = pw_hash
        db.session.commit()
        flash('Your password has been updated!.You may now log in here', 'success')
        if user.has_role('Association'):
            return redirect(url_for('users.login'))
        if user.has_role('Scholar'):
            return redirect(url_for('users.loginScholar'))
        else:
            return redirect(url_for('users.loginIndividual'))
        
    return render_template('reset/reset_token.html', title='Reset Password', form=form)
##################################Change and Reset#################################


