from datetime import timedelta, datetime
import secrets
from flask import Flask, current_app, render_template, url_for, flash, redirect, request, Blueprint, abort, session
#from hello import ShortenName
from webapp import db, bcrypt
from webapp.myadmin.forms import adm_form ,LoginForm, UpdateAdmForm, RequestResetForm, ResetPasswordForm, codeForm, EditUser
from webapp.models import User, Role, Post, Temp_user, Permission
from flask_login import login_user, current_user, logout_user, login_required, fresh_login_required, confirm_login
from webapp.utils import save_pic, send_email
from webapp.decorators import admin_required, permission_required, role_required
from flask_admin.helpers import is_safe_url

myadmin = Blueprint('myadmin', __name__)
#TODO dont_view/onlyAdmin my route
#TODO ==>> is_safe_url for Next
#todo: phone => nullble-false and Association

@myadmin.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)

@myadmin.route('/myadmin/')
@login_required
@admin_required
def all():
    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to visit that page', 'danger')
            return redirect(url_for('main.home'))
    elif not current_user.is_authenticated:
        abort(403)
    
    columns = ['edit', 'id', 'role', 'username', 'email', 'active', 'confirmed', 'last_seen', 'member_since', 'confirmed_at']

    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(page, per_page=20, error_out=False)
    users = user_table.items

    return render_template('myadmin/user_roles.html', active_all='active', users=users, columns=columns, user_table=user_table)


@myadmin.route('/myadmin/admin')
@login_required
@admin_required
def admin():
    #roles = Role.query.all()
    admin = Role.query.filter_by(name='admin').first()
    #Association = Role.query.filter_by(name='Association').first()
    #Scholar = Role.query.filter_by(name='Scholar').first()

    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to visit that page', 'danger')
            return redirect(url_for('main.home'))
    elif not current_user.is_authenticated:
        abort(403)
    users = User.query.filter_by(role=admin).all()
    columns = ['id','username', 'email', 'f_name', 'l_name', 'address', 'phone']

    #def gen_role():
    #    for i in range(len(roles)):
    #        role = roles[i].name
    #        yield role

    #roles = list(gen_role())


    #role = Role.query.filter_by(name=name).first_or_404()

    #page = request.args.get('page', 1, type=int)

    #users=User.query.filter_by(role=role)\
    #   .order_by(User.id.desc())\
    #   .paginate(per_page=5, page=page)
    
    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(per_page=4, page=page)

    return render_template('myadmin/user_roles.html', active_adm='active', users=users, columns=columns, user_table=user_table)

@myadmin.route('/myadmin/moderator')
@login_required
@role_required('admin')
@admin_required
def adminModerator():
    if not current_user.is_authenticated:
        abort(403)
        
    Moderator = Role.query.filter_by(name='Moderator').first()
    users = User.query.filter_by(role=Moderator).all()

    columns = ['id','username', 'email', 'f_name', 'l_name', 'address', 'phone']

    
    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(per_page=4, page=page)

    return render_template('myadmin/user_roles.html', active_mod='active', users=users, columns=columns, user_table=user_table)

@myadmin.route('/myadmin/scholar')
@login_required
@role_required('admin')
@admin_required
def adminScholar():
    if not current_user.is_authenticated:
        abort(403)
        
    Scholar = Role.query.filter_by(name='Scholar').first()
    users = User.query.filter_by(role=Scholar).all()

    columns = ['id','username', 'email', 'f_name', 'l_name', 'address', 'phone']

    
    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(per_page=4, page=page)

    return render_template('myadmin/user_roles.html', active_sch='active', users=users, columns=columns, user_table=user_table)

@myadmin.route('/myadmin/Association')
@login_required
@admin_required
def adminAssociation():
    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to visit that page', 'danger')
            return redirect(url_for('main.home'))
    elif not current_user.is_authenticated:
        abort(403)
        
    Association = Role.query.filter_by(name='Association').first()
    users = User.query.filter_by(role=Association).all()

    columns = ['id','username', 'email', 'or_name', 'shorten']

    
    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(per_page=4, page=page)

    return render_template('myadmin/user_roles.html', active_ass='active', users=users, columns=columns, user_table=user_table)

@myadmin.route('/myadmin/Individual')
@login_required
@admin_required
def adminIndividual():
    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to visit that page', 'danger')
            return redirect(url_for('main.home'))
    elif not current_user.is_authenticated:
        abort(403)
        
    Individual = Role.query.filter_by(name='Individual').first()
    users = User.query.filter_by(role=Individual).all()

    columns = ['id','username', 'email', 'address', 'phone' ]

    
    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(per_page=4, page=page)

    return render_template('myadmin/user_roles.html', active_ind='active', users=users, columns=columns, user_table=user_table)

@myadmin.route('/myadmin/temp_users')
@login_required
@admin_required
def temp_user():
    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to visit that page', 'danger')
            return redirect(url_for('main.home'))
    elif not current_user.is_authenticated:
        abort(403)
    users = Temp_user.query.all()

    columns = ['id','trole', 'code', 'temail', 'used']

    
    page = request.args.get('page', 1, type=int)
    user_table=User.query.order_by(User.id).paginate(per_page=4, page=page)

    return render_template('myadmin/user_roles.html', active_tem='active', users=users, columns=columns, user_table=user_table)



@myadmin.route('/myadmin/add', methods=['POST','GET'])
@login_required
@admin_required
@fresh_login_required
def add_admin():
    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to visit that page', 'danger')
            return redirect(url_for('main.home'))
    form=adm_form()
    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(f_name=form.f_name.data, address=form.address.data, l_name=form.l_name.data, phone=form.phone.data, email=form.email.data, username=str(form.email.data).split('@')[0], password=pw_hash)
        adm = Role.query.filter_by(name='admin').first()
        user.role = adm
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created. You may now log in here', 'success')
        return redirect(url_for('myadmin.all'))
    return render_template('myadmin/adm_add.html', active_all='active', form=form)





@myadmin.route('/myadmin/login', methods=['POST','GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user.has_role('admin'):
                abort(403)
        elif user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.has_role('admin'):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')

                #if not is_safe_url(next):
                #    abort(403)

                flash(f'Login successful. Welcome back {user.username}!', 'success')
                #if session.get('LastAccessed', None) is not None:
                #    print(session['LastAccessed'])
                #else:
                #    print('NO session')
                return redirect(next_page) if next_page else redirect(url_for('main.home'))

        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('myadmin/adm_login.html', title='Login', form=form, active_login='active')


##################################LOGOUT#################################
@myadmin.route('/logout')
@login_required
@admin_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))
##################################LOGOUT#################################



@myadmin.route('/myadmin/account', methods=['POST','GET'])
@login_required
@admin_required
def account():
    confirm_login()
    if current_user.has_role('Association'):
        return redirect(url_for('users.account'))
    elif current_user.has_role('Individual'):
        return redirect(url_for('users.accountIndividual'))
    elif current_user.has_role('Scholar'):
        return redirect(url_for('users.accountScholar'))
    elif not current_user.has_role('admin'):
        abort(403)
    form = UpdateAdmForm()
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
        return redirect(url_for('myadmin.account'))
    elif request.method == 'GET':
        form.f_name.data = current_user.f_name
        form.l_name.data = current_user.l_name
        form.address.data = current_user.address
        form.phone.data = current_user.phone
        form.username.data = current_user.username
    image_file = url_for('static', filename='img/' + current_user.image_file)
    return render_template('myadmin/account.html', title='account', ac_view='myadmin.account', active_account='active', image_file = image_file, form=form)



@myadmin.route('/myadmin/tempusercode/<string:user_role>', methods=['POST','GET'])
@admin_required
def register_code(user_role):
    if user_role != 'Scholar':
        if user_role != 'Association':
            abort(404)
    if current_user.is_authenticated:
        if not current_user.has_role('admin'):
            flash('You do not have any permission to do that thing', 'danger')
            return redirect(url_for('main.home'))
    form = codeForm()
    if form.validate_on_submit():
        if not current_user.has_role('admin'):
            abort(403)
        code_len = 6
        code = secrets.token_hex(20)[0:code_len]

        user = Temp_user.query.filter_by(code=code).first()
        if user:
            while user.code == code:
                code = secrets.token_hex(20)[0:code_len]

        user = Temp_user(temail=form.email.data, code=code, trole=user_role)
        db.session.add(user)

        tuser = Temp_user.query.filter_by(temail=form.email.data).first()

        token = tuser.code
        info = 'If you did not make this request then someone is trying to signup for an account with your email address'
        send_email(tuser.temail, 'Code For Register', 'email/send', user=tuser, info=info, code=token)
        db.session.commit()
        flash('An email has been sent. Tell him/her to check his email', 'success')
        return redirect(url_for('myadmin.account'))
    return render_template('myadmin/send_code.html', title=f'Add {user_role}', heading=f"Send code to {user_role}", form=form)
    
@myadmin.route('/myadmin/reset_password', methods=['POST','GET'])
def resetRequest():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user.has_role('admin'):
            abort(403)
        token = user.generate_token()
        info = 'If you did not make this request then simply ignore this email and no changes will be made'
        send_email(user.email, 'Reset Password', 'email/send', user=user, info=info, token=token, do='reset', what='password')
        flash('An email has been sent with intsructions to reset your password', 'success')
        return redirect(url_for('users.login'))
    return render_template('reset/reset_request.html', title='Reset Password', form=form)

@myadmin.route('/myadmin/reset_password/<token>', methods=['POST','GET'])
@admin_required
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



@myadmin.route('/myadmin/edit-user/<int:id>', methods=['POST','GET'])
@login_required
@admin_required
def edit_user(id):
    user = User.query.get_or_404(id)
    form = EditUser(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.active = form.active.data
        user.confirmed = form.confirmed.data
        print(f" This the role data frm the form ----{form.role.data}")
        role = Role.query.filter_by(id=form.role.data).first()
        print(f" This the selected role ----{role}")
        user.role = role
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated.', 'success')
        return redirect(url_for('myadmin.all'))
    form.email.data = user.email
    form.username.data = user.username
    form.active.data = user.active
    form.confirmed.data = user.confirmed
    form.role.data = user.role.id
    return render_template('myadmin/edit_user.html', form=form, user=user)
    