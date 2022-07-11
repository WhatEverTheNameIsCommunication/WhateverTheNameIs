from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField
from wtforms.validators import DataRequired
from flask_wtf.file import FileField, FileRequired


class WatermarkForm(FlaskForm):
    watermark = StringField('Watermark', validators=[DataRequired()])
    imagename = StringField('Imagename', validators=[DataRequired()])
    emailaddress = StringField('EmailAddress', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    text = StringField('Text', validators=[DataRequired()])