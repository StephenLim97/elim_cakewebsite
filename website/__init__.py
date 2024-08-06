from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from authlib.integrations.flask_client import OAuth

db = SQLAlchemy()
DB_Name ="database.db"
oauth = OAuth()

def create_database(app):
    if not path.exists('website/'+DB_Name):
        with app.app_context():
            db.create_all()
            print('Created Database!')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY']='lim xian zhu'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_Name}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    oauth.init_app(app)

    # Register the Google OAuth client
    oauth.register(
        name='google',
        client_id='627475411692-38jmo9sp9hl3h7lpdnsjlldqofjq3fde.apps.googleusercontent.com',
        client_secret='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',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,

        userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
        client_kwargs={'scope': 'openid profile email'},
        jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
    )

    from .auth import auth
    from .views import views
    app.register_blueprint(views, url_prefix='/')  # set as no prefix
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Information  # ensure the file is loaded
    create_database(app)


    login_manager = LoginManager()
    login_manager.login_view = "auth.Login"
    login_manager.init_app((app))

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app








