from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, InputRequired, ValidationError
from webapp.models import User

#TODO form inheretance

class AssociationForm(FlaskForm):
    or_name = StringField('Association Name', validators=[DataRequired(), Length(min=5)])
    shorten = StringField('Shorten', validators=[DataRequired(), Length(max=10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    #code also need some validation
    code = StringField(validators=[DataRequired(), Length(min=6, max=6)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('confirm Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Sign Up')

    def validate_or_name(self, or_name):
        user = User.query.filter_by(or_name=or_name.data).first()
        if user:
            raise ValidationError("This has already been taken. Please Choose a different one")
        
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("This has already been taken. Please Choose a different one")
        
    def validate_shorten(self, shorten):
        user = User.query.filter_by(shorten=shorten.data).first()
        if user:
            raise ValidationError("This has already been taken. Please Choose a different one")

class UpdateAssociationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5)])
    or_name = StringField('Association Name', validators=[DataRequired(), Length(min=5)])
    shorten = StringField('Shorten', validators=[DataRequired(), Length(max=10)])
    pic = FileField('Update Profile Picture', validators=[FileAllowed(['jpg','jpeg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("This username has already been taken. Please Choose a different one")

    def validate_or_name(self, or_name):
        if or_name.data != current_user.or_name:
            user = User.query.filter_by(or_name=or_name.data).first()
            if user:
                raise ValidationError("This name has already been taken. Please Choose a different one")
            
            
    def validate_shorten(self, shorten):
        if shorten.data != current_user.shorten:
            user = User.query.filter_by(shorten=shorten.data).first()
            if user:
                raise ValidationError("This has already been taken. Please Choose a different one")



#association ends

class ScholarForm(FlaskForm):
    f_name = StringField('First Name', validators=[DataRequired(), Length(min=3, max=20)])
    l_name = StringField('Surname', validators=[DataRequired(), Length(min=3, max=20)])
    address = StringField('Address', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email', validators=[Email()])
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

class UpdateScholarForm(FlaskForm):
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



class IndividualForm(FlaskForm):
    f_name = StringField('First Name', validators=[DataRequired(), Length(min=1, max=10)])
    l_name = StringField('Surname', validators=[DataRequired(), Length(min=1, max=10)])
    address = StringField('Address', validators=[DataRequired(), Length(min=1, max=10)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=1, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])
    phone = StringField('phone', validators=[DataRequired(), Length(min=1, max=10)])
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

class UpdateIndividualForm(FlaskForm):
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
                raise ValidationError("This Phone number already exists. Please Choose a different one")
        

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')

#todo enter the last password you remember
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Request Reset Passsword')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError("There is NO account with this email. Please register")

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password'), Length(min=8)])
    submit = SubmitField('Reset Passsword')

class ChangePasswordForm(FlaskForm):
    password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password'), Length(min=8)])
    submit = SubmitField('Change Passsword')
    
class ChangeEmailForm(RequestResetForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Change Email')
    