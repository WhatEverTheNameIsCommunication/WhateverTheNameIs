

from flask import redirect, render_template, send_from_directory, current_app,request,flash,url_for
from flask_login import login_required
from littleRedCUC.forms import SignUpForm
from littleRedCUC.db_models import User,db
from littleRedCUC.blueprints import anony

@anony.route('/')
def home():
    return render_template('layout.html')



@anony.route('/posts',methods=['GET', 'POST'])
def force_to_login():
    return render_template('/auth/login.html')


@anony.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm(request.form)
    if request.method == 'POST' :
        print(22222)
    # and form.validate():
        user=User(form.email.data,form.password.data)
        db.session.add(user)
        flash('welcome to littleRedCUC')
        return redirect(url_for('auth.layout'))
    return render_template('signup.html',form=form)


@anony.route('/images/<image_name>')
def images(image_name):
    try:
        return send_from_directory(current_app.config["UPLOAD_FOLDER"],
                                   path=image_name)
    except FileNotFoundError:
        abort(404)