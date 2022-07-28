# -*- coding: UTF-8 -*-

import os
from flask import Flask, redirect, url_for
from flask.cli import AppGroup
import click
from pathlib import Path

# from littleRedCUC.flask_adminlte import AdminLTE
from flask import Flask

from importlib import import_module
from littleRedCUC.blueprints import all_blueprints


from littleRedCUC.blueprints import all_blueprints
# from littleRedCUC.views.resources import api_bp
from littleRedCUC.extensions import login_manager,db,bcrypt,migrate

from littleRedCUC.db_models import User,UserRole
from config import config

def create_app():
    flask_app = Flask(__name__, instance_relative_config=True)
    # AdminLTE(flask_app)
    flask_app.config['SECRET_KEY']='littleRedCUC'
    flask_app.config['SERVER_NAME']='sec.whateveritis.cuc.edu.cn:5000'
    config_name = os.getenv('FLASK_CONFIG', 'default')
    flask_app.config.from_object(config[config_name])
    flask_app.config.from_pyfile('app.cfg', silent=True)

    upload_path = Path(flask_app.instance_path) / 'upload'
    if not Path(flask_app.instance_path).exists():
        Path(flask_app.instance_path).mkdir()
    if not upload_path.exists():
        upload_path.mkdir()

    # 存放给用户下载文件的目录
    download_path = Path(flask_app.instance_path) / 'download'
    if not Path(flask_app.instance_path).exists():
        Path(flask_app.instance_path).mkdir()
    if not download_path.exists():
        download_path.mkdir()

    # 存放给用户分享码加密后的文件
    shared_path = Path(flask_app.instance_path) / 'shared'
    if not Path(flask_app.instance_path).exists():
        Path(flask_app.instance_path).mkdir()
    if not shared_path.exists():
        shared_path.mkdir()
    
    # 存放系统文件
    system_path = Path(flask_app.instance_path) / 'system'
    if not Path(flask_app.instance_path).exists():
        Path(flask_app.instance_path).mkdir()
    if not system_path.exists():
        system_path.mkdir()

    flask_app.config['UPLOAD_FOLDER'] = str(upload_path)
    flask_app.config['DOWNLOAD_FOLDER'] = str(download_path)
    flask_app.config['SHARED_FOLDER'] = str(shared_path)
    flask_app.config['SYSTEM_FOLDER'] = str(system_path)

    login_manager.session_protection = 'AdminPassword4Me'
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Unauthorized User.'
    login_manager.login_message_category = "info"

    login_manager.init_app(flask_app)
    db.init_app(flask_app)
    bcrypt.init_app(flask_app)
    migrate.init_app(flask_app, db)

    for bp in all_blueprints:
        import_module(bp.import_name)
        flask_app.register_blueprint(bp)
    # flask_app.register_blueprint(api_bp)

    user_cli = AppGroup('user')


    @user_cli.command('create-admin')
    @click.argument('email')
    @click.argument('name')
    @click.argument('password')
    
    def create_admin(email, name, password):
        user = User(email=email,
                    # email_confirmed=True,
                    name=name,
                    role=UserRole.ADMIN)
        user.password = password

        db.session.add(user)
        db.session.commit()

    flask_app.cli.add_command(user_cli)

    return flask_app

if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host='0.0.0.0',port=5000, debug=True,ssl_context=("./x.509/intermediate/certs/whateveritis.cuc.edu.cn.cert.crt", './x.509/intermediate/private/whateveritis.cuc.edu.cn.key.pem'))