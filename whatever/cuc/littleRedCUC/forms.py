# -*- coding: UTF-8 -*-
from email import message
from wsgiref.validate import validator
from xml.dom import ValidationErr
from flask_wtf import FlaskForm
from flask_wtf.file import FileSize, FileAllowed
from wtforms import StringField, PasswordField,validators,SubmitField,TextAreaField,FileField,DateField,IntegerField
from wtforms.validators import DataRequired, Email,Length,EqualTo
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
    emailway=SubmitField('Email')
    goole=SubmitField('Google') 


class SignUpForm(FlaskForm):
    # email = StringField('Email  Adress', validators=[DataRequired(), Email(),Unique(User,User.email)])
    # password = PasswordField('Password', validators=
    # [
    #     validators.DataRequired(),
    #     validators.EqualTo('confirm',message='Passwords must match')
    # ])
    # confirm = PasswordField('Repeat Password')
    # user_name = StringField('user_name',validators=[DataRequired()])
    email = StringField('邮箱', validators=[DataRequired(), Email(),Unique(User,User.email)])
    password = PasswordField('密码', validators=[DataRequired(),Length(min=8,max=36)])
    confirm=PasswordField('确认密码',validators=[DataRequired(),EqualTo('password',message='必须和密码已输入密码相同')])
    user_name= StringField('用户名',validators=[DataRequired()])



class VertifyForm(FlaskForm):
    vc = StringField('验证码', validators=[DataRequired()])
    email = StringField('邮箱', validators=[DataRequired(), Email()])



class FindForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Email()])



class ChangepasswdForm(FlaskForm):
    email = StringField('邮箱', validators=[DataRequired(), Email()])
    password = PasswordField('密码', validators=[DataRequired(),Length(min=8,max=36)])
    confirm=PasswordField('确认密码',validators=[DataRequired(),EqualTo('password',message='必须和密码已输入密码相同')])



suffix=['jpeg','jpg','png','bmp','gif','doc','docx','ppt','pptx','xls','xlsx','pdf']
class PostForm(FlaskForm):
    text=TextAreaField('描述文本',validators=[DataRequired()])
    file=FileField('上传文件',validators=[DataRequired(),FileSize(1024*1024*10,0,message='过大'),FileAllowed(suffix,'非法文件')])


class ShareForm(FlaskForm):
    date=DateField('截止日期',validators=[DataRequired()],format="%Y-%m-%d")
    times=IntegerField("下载次数")