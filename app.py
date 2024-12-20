from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import ForeignKey
import jwt
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cd_collection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

class Countries(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, unique=True)
    country = db.Column(db.String(80), nullable=False, unique=True)
    alpha2 = db.Column(db.String(2), nullable=True)
    alpha3 = db.Column(db.String(3), nullable=True)
    region = db.Column(db.String(20), nullable=True)

def present_countries(countries):
    return {
        'name': countries.name,
        'alpha2': countries.alpha2,
        'alpha3': countries.alpha3,
        'region': countries.region
    }

def present_user(user):
    return {
        'login': user.login,
        'email': user.email,
        'password': user.password,
        'countryCode': user.countryCode,
        'isPublic': user.isPublic,
        'phone': user.phone,
        'image': user.image
    }

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, unique=True)
    login = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(40), nullable=False)
    countryCode = db.Column(db.String(2), nullable=False, unique=True)
    isPublic = db.Column(db.Boolean)
    phone = db.Column(db.String(12), nullable=False, unique=True)
    image = db.Column(db.String(40), nullable=True)

@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200

@app.route('/countries', methods=['GET'])
def countries():
    countries = Countries.query.all()
    country_descriptions = [present_countries(country) for country in countries]
    return jsonify(country_descriptions), 200

@app.route('/countries/<alpha2>', methods=['GET'])
def alpha2(alpha2):
    country = Countries.query.filter_by(alpha2=alpha2).first()
    if not country:
        return jsonify({'reason': 'Country not found'}), 404
    return jsonify(present_countries(country)), 200

@app.route('/auth/register', methods=['POST'])
def add_user():
    data = request.get_json()

    if data is None:
        return jsonify({'reason': 'Invalid JSON format'}), 400

    login = data.get('login')
    email = data.get('email')
    password = data.get('password')
    isPublic = data.get('isPublic')
    phone = data.get('phone')
    image = data.get('image')
    countryCode = data.get('countryCode')
    country = Countries.query.filter_by(alpha2=countryCode).first()
    if not login:
        return jsonify({'reason': 'Missing name'}), 400
    if not password:
        return jsonify({'reason': 'Missing password'}), 400
    if User.query.filter_by(login=login).first():
        return jsonify({'reason': 'User already exists'}), 409
    if not country:
        return jsonify({'reason': 'Country not found'}), 400
    if User.query.filter_by(phone=phone).first():
        return jsonify({'reason': 'User with this phone already exists'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'reason': 'User with this email already exists'}), 409
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(login=login, email=email, password=hashed_password, coutryCode=countryCode, isPublic=isPublic, phone=phone, image=image)
    db.session.add(user)
    db.session.commit()

    return jsonify({'porfile':present_user(user)}), 201

@app.route('/auth/sign-in', methods=['POST'])
def login():
    data = request.get_json()

    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Missing data'}), 400

    user = User.query.filter_by(login=login).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({'user_id': user.id, 'created_at': int(time.time())}, app.config['SECRET_KEY'],
                       algorithm='HS256')

    return jsonify({'token': token}), 200

if __name__ == "__main__":
    app.run()
