# -*- coding: UTF-8 -*-
from email import message
from wsgiref.validate import validator
from xml.dom import ValidationErr
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,validators
from wtforms.validators import DataRequired, Email
from littleRedCUC.db_models import User

# 添加邮箱唯一验证
class Unique(object):
    def __init__(self,model,field,message=u'该用户已存在'):
        self.model = model
        self.field = field
        self.message=message
    

    def __call__(self,form,field):
        check = self.model.query.filter(self.field==field.data).first()
        if check:
            raise ValidationErr(self.message)

class SignInForm(FlaskForm):
    email = StringField('Email  Adress', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class SignUpForm(FlaskForm):
    email = StringField('Email  Adress', validators=[DataRequired(), Email(),Unique(User,User.email)])
    password = PasswordField('Password', validators=
    [
        validators.DataRequired(),
        validators.EqualTo('confirm',message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')



