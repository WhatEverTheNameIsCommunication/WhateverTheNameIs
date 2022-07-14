# -*- coding: UTF-8 -*-
from optparse import Option
from flask import render_template, redirect, url_for, request,make_response
from flask_login import LoginManager, login_required, login_user, logout_user
import csv
import os
import pandas as pd
import numpy as np
from app import TotpFactory
from app.auth.forms import SignInForm
from app.auth.forms import SignUpForm
from app.auth.forms import VertifyForm
from app.blueprints import auth
from app.user.models import User
from app.emailway import generateToken,sendMail,vertifToken
from app.extensions import db
from app.extensions import login_manager


@login_manager.user_loader
def load_user(userid):
    return User.query.filter(User.id == userid).first()


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = SignInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        if user.is_correct_password(form.password.data):
            if form.emailway.data:
                # flash('You choose email way')
                # totp=generateToken()
                totp=TotpFactory.new()
                data=totp.to_json()
                # totp = TOTP.from_source(data)
                sendMail(totp.generate().token,'','','',form.email.data,'')
                # 存文件cv2???里传参....
                headers=['email_address','totp']
                data = [form.email.data, data]
                with open('2FA.csv', mode='a', newline='', encoding='utf-8-sig') as f:
                        csv_writer = csv.writer(f, delimiter=',')
                        if not os.path.getsize('2FA.csv'):    
                            csv_writer.writerow(headers)
                        csv_writer.writerow(data)
                # sendMail(message,Subject,sender_show,recipient_show,to_addrs,cc_show='')
            elif form.goole.data:
                print('You choose goole way')
            # return redirect(url_for('auth.authentic',user_email=form.email.data,key=totp))
            return redirect(url_for('auth.authentic'))
            # login_user(user)

            # next = request.args.get('next')
            # return redirect(next or url_for('home.index'))
        else:
            return redirect(url_for('auth.login'))

    return render_template('auth/login.html', form=form)

# @auth.route('/2fa/?<string:user_email>?<string:key>', methods=['GET', 'POST'])
#             # '/home/?<string:messages>'
# def authentic(user_email,key):
#     form = VertifyForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=user_email)
#         if vertifToken(form.vc.data,key):
#             login_user(user)
#             return redirect(url_for('home.index'))
#     # form.email.data=user_email
#     # form.key.data=key
#     return render_template('auth/2fa.html',form=form)

@auth.route('/2fa', methods=['GET', 'POST'])
def authentic():
    form = VertifyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        matrix=pd.read_csv('D:/homework-2022-s/XiaoXueQI/zcfxc/0x09_InstaCUC/2FA.csv')# D:/homework-2022-s/XiaoXueQI/zcfxc/0x09_InstaCUC/2FA.csv
        matrix=np.array(matrix)
        a=matrix.shape[0]
        for i in range(a-1,-1,-1):
            if matrix[i][0]==form.email.data:
                key=matrix[i][1]
                break
        print(key)
        print(form.vc.data)
        if vertifToken(form.vc.data,key):
            login_user(user)
            return redirect(url_for('home.index'))
        return redirect(url_for('auth.authentic'))
    return render_template('auth/2fa.html',form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully!'
