from flask import Blueprint, render_template, request,flash,jsonify, redirect, url_for, session
from flask_login import login_required, current_user
from .models import Information, db, User
from werkzeug.security import check_password_hash, generate_password_hash
# from .import db
# import json
import os
views = Blueprint('views', __name__)


@views.route('/SignInWithoutAccount', methods=['GET', 'POST'])
def SignInWithoutAcccount():
    print("Login without user")
    session['login_with_user'] = False
    return redirect(url_for('views.Home'))


@views.route('/SignInWithAccount', methods=['GET', 'POST'])
@login_required
def SignInWithAcccount():
    print("Login with user")
    session['login_with_user'] = True
    return redirect(url_for('views.Home'))


@views.route('/', methods=['GET', 'POST'])
def Home():
    image_dir = os.path.join(views.root_path, 'static', 'img/sub_tittle')
    try:
        # List all .gif files in the image directory
        images = [img for img in os.listdir(image_dir) if img.endswith('.gif')]

    except FileNotFoundError:
        # If the directory does not exist, return an empty list
        images = []

    login_with_user = session.get('login_with_user', False)
    done_logout = False  # Adjust this logic as needed

    return render_template('Home.html', images=images, user=current_user, done_logout=done_logout,
                           login_with_user=login_with_user)


@views.route('/EditProfile',methods=['GET', 'POST'])
def EditProfile():

    if request.method == 'POST':
        updateProfile = request.form.get('updateProfile')
        # print('update profile status', updateProfile)
        # Check if user already has an Information entry
        # user = Information.query.filter_by(user_id=current_user.id).first()
        user = User.query.filter_by(id=current_user.id).first()

        if updateProfile =='editProfile':
            # print('edit profiel page')
            phone = request.form.get('phone')
            street = request.form.get('street')
            state = request.form.get('state')
            city = request.form.get('city')
            zipcode = request.form.get('zipCode')



            if user:
                # Update existing information
                user.phone = phone
                user.street = street
                user.state = state
                user.city = city
                user.zipcode = zipcode
            else:
                # Create new information entry
                new_info = Information(
                    phone=phone,
                    street=street,
                    state=state,
                    city=city,
                    zipcode=zipcode,
                    user_id=current_user.id
                )
                db.session.add(new_info)
        elif updateProfile == 'changePassword':
                current_password=request.form.get('currentPassword')

                if check_password_hash(user.password, current_password):
                    print('current password sucess:', current_password)
                    password1 = request.form.get('newPassword')
                    password2 = request.form.get('confirmPassword')

                    if password1 != password2:
                        flash('Passwords don\'t match.', category='error')
                    elif len(password1) < 7:
                        flash('Password must be at least 7 character.', category='error')
                    else:
                        # Update the existing user's password
                        user.password = generate_password_hash(password1)
                        flash('Password Changed', category='sucess')
                else:
                    flash('Wrong password provide for current', category='error')
        db.session.commit()
    if current_user.is_authenticated:
        done_logout=False
        login_with_user = True
    else:
        done_logout=False
        login_with_user = False
    user_info = Information.query.filter_by(user_id=current_user.id).first()
    return render_template("Profile.html", user=current_user, done_logout=done_logout,
                           login_with_user=login_with_user, information =user_info)