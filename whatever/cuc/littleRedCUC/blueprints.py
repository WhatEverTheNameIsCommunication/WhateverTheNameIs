from flask import Blueprint

anony = Blueprint('anony','littleRedCUC.views.anony',url_prefix='/')

auth = Blueprint('auth','littleRedCUC.views.auth',url_prefix='/auth')

all_blueprints={
    anony,
    auth,
}