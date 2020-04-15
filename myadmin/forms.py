from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, InputRequired, ValidationError, Regexp
from webapp.models import Role, User, Temp_user



class adm_form(FlaskForm):
    f_name = StringField('First Name', validators=[DataRequired(), Length(min=3, max=20)])
    l_name = StringField('Surname', validators=[DataRequired(), Length(min=3, max=20)])
    address = StringField('Address', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email', validators=[Email(), Length(max=20)])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=7, max=12)])
    code = StringField(validators=[DataRequired(), Length(min=6, max=6)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=8)])
    submit = SubmitField('Sign Up')

    def validate_phone(self, phone):
        user = User.query.filter_by(phone=phone.data).first()
        if user:
            raise ValidationError("This Phone number already exists. Please choose a different one")
        
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("This has already been taken. Please Choose a different one")

class UpdateAdmForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5)])
    f_name = StringField('First Name', validators=[ Length(min=2)])
    l_name = StringField('Last Name', validators=[ Length(min=2)])
    address = StringField('Address', validators=[ Length(max=20)])
    phone = StringField('Phone', validators=[ Length(max=10)])
    pic = FileField('Update Profile Picture', validators=[FileAllowed(['jpg','jpeg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("This username has already been taken. Please Choose a different one")
            
            
    def validate_phone(self, phone):
        if phone.data!= current_user.phone:
            user = User.query.filter_by(phone=phone.data).first()
            if user:
                raise ValidationError("This has already been taken. Please Choose a different one")




class codeForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Send Code')

    def validate_email(self, email):
        tuser = Temp_user.query.filter_by(temail=email.data).first()
        user = User.query.filter_by(email=email.data).first()
        if user or tuser:
            raise ValidationError("This email already exists. Please check what you typed")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Request Reset Passsword')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError("There is account with this email. Please register")

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=8)])
    submit = SubmitField('Reset Passsword')

class EditUser(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1, 64),
    Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or '
    'underscores')])
    active = BooleanField('Active')
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    submit = SubmitField('Submit')
    
    
    def __init__(self, user, *args, **kwargs):
        super(EditUser, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                            for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError("Email already registered.")
    
    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')
    
