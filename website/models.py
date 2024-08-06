from . import db
from flask_login import UserMixin

from sqlalchemy.sql import func
from authlib.integrations.flask_client import OAuth


class Information(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(150))
    street = db.Column(db.String(150))
    state = db.Column(db.String(150))
    city = db.Column(db.String(150))
    zipcode = db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    information = db.relationship('Information', backref='user', uselist=False)