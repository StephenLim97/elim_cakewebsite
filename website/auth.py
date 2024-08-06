from flask import Blueprint, render_template, request, flash, redirect, url_for,session
from.models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user,login_required, logout_user, current_user
import os
from .import db, oauth
from authlib.integrations.flask_client import OAuth
import uuid


auth = Blueprint('auth', __name__)



# google register start ===================================================================================
google = oauth.register(
    name='google',
    client_id='your_google_client_id',
    client_secret='your_google_client_secret',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid profile email'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'  # Ensure this line is present

)


@auth.route('/google_login')
def google_login():
    # Generate a nonce
    nonce = str(uuid.uuid4())
    # Store the nonce in the session
    session['nonce'] = nonce
    session['auth_type'] = 'login'
    redirect_uri = url_for('auth.google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@auth.route('/google_register')
def google_register():
    # Generate a nonce
    nonce = str(uuid.uuid4())
    # Store the nonce in the session
    session['nonce'] = nonce
    session['auth_type'] = 'register'
    redirect_uri = url_for('auth.google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

@auth.route('/google_authorize')
def google_authorize():
    try:
        token = google.authorize_access_token()
        # Retrieve the nonce from the session
        nonce = session.pop('nonce', None)
        if not nonce:
            return 'Nonce not found in session', 400
        # Pass the nonce to parse_id_token
        user_info = google.parse_id_token(token, nonce=nonce)

        # Check if the user exists in the database
        user = User.query.filter_by(email=user_info['email']).first()

        if session.pop('auth_type', None) == 'register':
            if user:
                flash('Email already exists.', category='error')
                return redirect(url_for('auth.Login'))
            # If user does not exist, create a new user
            else:
                user = User(
                    email=user_info['email'],
                    name=user_info['name'],
                    password=generate_password_hash(os.urandom(16).hex())  # Generate a random password
                )
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return redirect(url_for('views.SignInWithAcccount'))
        else:
            if user:
                login_user(user)
                return redirect(url_for('views.SignInWithAcccount'))

            # If user does not exist, create a new user
            else:
                flash('Email not exist', category='error')
                return redirect(url_for('auth.Login'))


    except Exception as e:
        print("Exception:", e)  # Log any exception that occurs
        return str(e)

# google register end ==================================================================================

# facebook register start =============================================================================

facebook = oauth.register(
    name='facebook',
    client_id='7597762540313099',
    client_secret='3fad30b1aa7d49b95692241c244bc9af',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    userinfo_endpoint='https://graph.facebook.com/me?fields=id,name,email',
    client_kwargs={'scope': 'email'},
)


@auth.route('/facebook_login')
def facebook_login():
    session['auth_type'] = 'login'
    redirect_uri = url_for('auth.facebook_authorize', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@auth.route('/facebook_register')
def facebook_register():
    session['auth_type'] = 'register'
    redirect_uri = url_for('auth.facebook_authorize', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@auth.route('/facebook_authorize')
def facebook_authorize():
    try:
        token = facebook.authorize_access_token()
        resp = facebook.get('userinfo', token=token)
        user_info = resp.json()

        # Check if the user exists in the database
        user = User.query.filter_by(email=user_info['email']).first()

        if session.pop('auth_type', None) == 'register':
            if user:
                flash('Email already exists.', category='error')
                return redirect(url_for('auth.login'))
            else:
                user = User(
                    email=user_info['email'],
                    name=user_info['name'],
                    password=generate_password_hash(os.urandom(16).hex())  # Generate a random password
                )
                db.session.add(user)
                db.session.commit()
                login_user(user)
                return redirect(url_for('views.home'))
        else:
            if user:
                login_user(user)
                return redirect(url_for('views.home'))
            else:
                flash('Email not registered.', category='error')
                return redirect(url_for('auth.login'))

    except Exception as e:
        print("Exception:", e)  # Log any exception that occurs
        return str(e)


# facebook register end ===================================================================================
@auth.route('/Example1')
def Example1():
    return render_template('Example1.html')

@auth.route('/SlideExample')
def Example2():
    return render_template('SlideExample.html')

@auth.route('/TestingPage')
def TestingPage():
    # Get the absolute path to the image directory
    image_dir = os.path.join(auth.root_path, 'static', 'img/sub_tittle')
    try:
        # List all .gif files in the image directory
        images = [img for img in os.listdir(image_dir) if img.endswith('.gif')]
    except FileNotFoundError:
        # If the directory does not exist, return an empty list
        images = []
    return render_template('TestingPage.html', images=images)

@auth.route('/Login' , methods =['GET','POST'])
def Login():
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'create_account':
            print('created account')
            email = request.form.get('email_create')
            name = request.form.get('name')
            print("name Login", name)
            print("email Email", email)
            password1 = request.form.get('password1')
            password2 = request.form.get('password2')

            user = User.query.filter_by(email=email).first()
            print("user", user)
            if user:
                flash('Email already exist.', category='error')
            elif len(name) > 10:
                flash("Name created must not exist than 10 character")
            elif len(email) < 4:
                flash('Email must be greater than 3 character', category='error')
            elif len(name) < 2:
                flash('First Name must be greater than 1', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 character.', category='error')
            else:
                new_user = User(email=email, first_name=name, password=generate_password_hash(password1))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.Home'))

        elif form_type =='sign_in':
            email_sign_in = request.form.get('email_sign_in')
            password_sign_in = request.form.get('password_sign_in')
            user = User.query.filter_by(email=email_sign_in).first()
            if user:
                if check_password_hash(user.password, password_sign_in):
                    flash('Logged in sucessfully', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.SignInWithAcccount'))

                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                flash('Email does not exist.', category='error')
        # return render_template("login.html", user=current_user)
    return render_template('Login.html', user=None, done_logout=True)

@login_required
@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.Login'))


