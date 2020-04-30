from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, InputRequired




class JoinForm(FlaskForm):
    why_join = TextAreaField('WHY DO YOU WANT TO JOIN THE ASSOCIATION?', validators=[DataRequired()])
    want_to_achieve = TextAreaField('WHAT DO YOU WANT TO ACHIEVE IN THE ASSOCIATION?', validators=[DataRequired()])
    willing_to_offer = TextAreaField('WHAT ARE YOU WILLING TO OFFER IF YOU HAPPEN TO BE ONE OF OUR MEMBERS?', validators=[DataRequired()])
    declare = BooleanField('', validators=[InputRequired()])
    submit = SubmitField('Submit Application')

