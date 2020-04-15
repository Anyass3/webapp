from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, InputRequired




class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    img_file = FileField('Update Image', validators=[FileAllowed(['jpg','jpeg', 'png'])])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

