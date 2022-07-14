from passlib.totp import TOTP
# from requests.auth import HTTPBasicAuth
import smtplib
# from smtplib import SMTP_SSL
from email.mime.text import MIMEText
import os

from app import TotpFactory
# 生成一次性密钥
def generateToken():
    # totp = TOTP(key=None,format="base32", new=True,digits = 6, alg = "sha512",period=60)
    # # (key=None, format="base32", *, new=False, **kwdspasslib.totp.TOTP)
    # totp.generate()
    # password = totp.generate().token
    # time=totp.generate().expire_time
    # print (password)    
    # print (totp.generate().expire_time)
    # return totp
    totp=TotpFactory.new()
    data=totp.to_json()
    return data
    #totp = TotpFactory.from_source(data)
    # >>> totp.base32_key
    # 'FLEQC3VO6SIT3T7GN2GIG6ONPXADG5CZ'
 
# 认证
def vertifToken(token,source):
    # try:
    #     totp.match(code,time=totp.generate().expire_time) #使用
    #     print ('success')
    #     return True
    # except Exception as err:
    #     print ("False")
    #     return False
    try:
        match = TotpFactory.verify(token, source)
        # totp.match(token,time=totp.generate().expire_time) #使用
        print (match)
        return True
    except Exception as err:
        return False


 
def sendMail(message,Subject,sender_show,recipient_show,to_addrs,cc_show=''):
    '''
    :param message: str 邮件内容
    :param Subject: str 邮件主题描述
    :param sender_show: str 发件人显示，不起实际作用如："xxx"
    :param recipient_show: str 收件人显示，不起实际作用 多个收件人用','隔开如："xxx,xxxx"
    :param to_addrs: str 实际收件人
    :param cc_show: str 抄送人显示，不起实际作用，多个抄送人用','隔开如："xxx,xxxx"
    '''
    # 填写真实的发邮件服务器用户名、密码
    user = '1092265772@qq.com'
    password = 'twfsspcabwvzgjei'
    # 邮件内容
    msg = MIMEText(message, 'plain', _charset="utf-8")
    # 邮件主题描述
    msg["Subject"] = Subject
    # 发件人显示，不起实际作用
    msg["from"] = sender_show
    # 收件人显示，不起实际作用
    msg["to"] = recipient_show
    # 抄送人显示，不起实际作用
    msg["Cc"] = cc_show
    with smtplib.SMTP_SSL(host="smtp.qq.com",port=465) as smtp:
        # 登录发邮件服务器
        smtp.login(user = user, password = password)
        # 实际发送、接收邮件配置
        smtp.sendmail(from_addr = user, to_addrs=to_addrs.split(','), msg=msg.as_string())
 
if __name__ =='__main__':
    # (key=None, format="base32", *, new=False, **kwdspasslib.totp.TOTP)
    totp=generateToken()
    print (totp)    

    message = totp
    Subject = '主题测试'
    # 显示发送人
    sender_show = 'xxx'
    # 显示收件人
    recipient_show = 'xxx'
    # 实际发给的收件人
    to_addrs = '1092265772@qq.com'
    sendMail(message,Subject,sender_show,recipient_show,to_addrs)