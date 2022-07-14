# -*- coding: UTF-8 -*-
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,SubmitField
from wtforms.validators import DataRequired, Email


class SignInForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    emailway=SubmitField('Email')
    goole=SubmitField('Goole') 


class SignUpForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired()])

class VertifyForm(FlaskForm):
    vc = StringField('验证码', validators=[DataRequired()])
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    # key = StringField('totp', validators=[DataRequired()])
