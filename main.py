"""

BEFORE YOU PUT THIS UP AND RUNNING, YOU NEED TO HAVE:

1) MQTT BROKER (OR SOME PUBLIC BROKER)
2) run python -m pip install -r requirementst.txt
3) rename .env.example to .env
4) put your mongodb url there


5) run create_admin.py
6) provide username and password

7) run create_iot.py
8) provide username and password
9) add the output from this script into client2 projects .env file as TOKEN

10) RUN python main.py

11) GO TO CLIENT1
12) run python -m pip install -r requirements.txt
13) rename .env.example to .env
14) write your MONGODB_URL there
15) look for other configurations in main.py that need to be changed
16) run python main.py



17) GO TO CLIENT2
18) run python -m pip install -r requirements.txt
19) rename .env.example to .env
20) write your MONGODB_URL there
21) look for oter configurations you need to change
22) run python main.py




"""

import os
import time
import uuid

import jwt
from bson import ObjectId
from dotenv import load_dotenv
from passlib.context import CryptContext
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask import Flask, request, jsonify

from iot_token import AsymmetricToken

app = Flask(__name__)

client = None
db = None

# this to for encrypting passwords
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


# this is to check if user is logged in
# this is a decoreator, you can use in every routehandler like this
# @app.route('/api/v1/account')
# @require_login
# def account():
# get users account here

def require_login(f):
    def wrapper(*args, **kwargs):
        try:

            auth_header = request.headers.get('Authorization')

            bearer, access_token = auth_header.split(' ')

            _token = AsymmetricToken()
            account = _token.validate(access_token)
            logged_in_user = db.users.find_one({'_id': ObjectId(account['sub'])})
            logged_in_user['_id'] = str(logged_in_user['_id'])
            return f(logged_in_user, *args, **kwargs)
        except Exception as _e:
            print(_e)
            return jsonify(({'err': 'Unauthorized'})), 401

    return wrapper


# this is to check that logged in user is of certain role
# this is another decorator
# has to always be used with require_login
def require_role(role='user'):
    def decorator(f):
        def wrapper(account, *args, **kwargs):
            if account['role'] == role:
                return f(account, *args, **kwargs)
            return jsonify({'err': 'forbidden'}), 403

        return wrapper

    return decorator


# this if for getting stored sensor data
@app.route('/api/v1/sensordata', methods=['GET'])
def get_sensor_data():
    if request.method == 'GET':
        data = db.sensor_data.find({})
        sensordata = []
        for row in data:
            row['_id'] = str(row['_id'])
            sensordata.append(row)

        return jsonify({'data': sensordata})


# this endpoint is for storing sensor data coming from mqqt client
# requires logged in user (a valid access_token)
# and that the user has to be of role 'iot'
@app.route('/api/v1/iot/sensordata', methods=['POST'], endpoint='postdata')
# this is here to ensure, that user is logged in and has role iot
@require_login
@require_role('iot')
def post_sensor_data(account):
    body = request.get_json()
    db.sensor_data.insert_many(body)
    return "", 201


# this is for admin to be able to add iot users
# this is only for admins to be used
# you can create an admin user for yourself running create_admin.py script


# iot users are needed for storing data from mqtt client into database

"""

example request body

{
	"username": "iotdevice",
	"password": "salasana"
}

content-type: application/json

"""


@app.route('/api/v1/admin/register', methods=['POST'])
@require_login
@require_role('admin')
def register_iot(account):
    try:

        req_body = request.get_json()
        user = db.users.find_one({'username': req_body['username']})
        if user is not None:
            raise Exception('Username is taken')
        db.users.insert_one(
            {'username': req_body['username'], 'password': bcrypt_context.hash(req_body['password']), 'role': 'iot'})
        return "", 201
    except Exception as e:
        print(e)
        return jsonify({'err': str(e)}), 500


# here you can register new users
# here you can register what ever uses if you wish
# this is here as an example

"""

example request body

{
	"username": "newuser",
	"password": "salasana"
}

content-type: application/json

"""


@app.route('/api/v1/register', methods=['POST'])
def register_user():
    try:
        req_body = request.get_json()
        user = db.users.find_one({'username': req_body['username']})
        if user is not None:
            raise Exception('Username is taken')
        db.users.insert_one(
            {'username': req_body['username'], 'password': bcrypt_context.hash(req_body['password']), 'role': 'user'})
        return "", 201
    except Exception as e:
        print(e)
        return jsonify({'err': str(e)}), 500


# this is for creating new access_tokens for iot users
# after registering new iot user, get a new access_token for that user using this endpoint


"""

example request body

{
	"username": "iotdevice",
	"password": "salasana"
}

content-type: application/json

"""


@app.route('/api/v1/token', methods=['POST'])
def get_token():
    req_body = request.get_json()
    user = db.users.find_one({'username': req_body['username']})
    if user is None:
        return jsonify({'err': 'User not found'}), 404

    valid = bcrypt_context.verify(req_body['password'], user['password'])
    if not valid:
        return jsonify({'err': 'User not found'}), 404
    _token = AsymmetricToken()

    access_token = _token.create(
        {'type': 'access', 'role': user['role'], 'exp': None, 'sub': str(user['_id']), 'csrf': None})

    return jsonify({'access_token': access_token})


"""

example request body

{
	"username": "admin",
	"password": "salasana"
}

content-type: application/json

"""


# this is to login users
@app.route('/api/v1/login', methods=['POST'])
def login_user():
    req_body = request.get_json()
    user = db.users.find_one({'username': req_body['username']})
    if user is None:
        return jsonify({'err': 'User not found'}), 404

    valid = bcrypt_context.verify(req_body['password'], user['password'])
    if not valid:
        return jsonify({'err': 'User not found'}), 404
    _token = AsymmetricToken()
    csrf = str(uuid.uuid4())
    access_token = _token.create(
        {'type': 'access', 'role': user['role'], 'exp': time.time() + 3600, 'sub': str(user['_id']), 'csrf': csrf})
    refresh_token = _token.create(
        {'type': 'refresh', 'exp': time.time() + 3600 * 24 * 7, 'sub': str(user['_id']), 'csrf': None})

    return jsonify({'access_token': access_token, 'refresh_token': refresh_token})


if __name__ == '__main__':
    load_dotenv()
    uri = os.getenv('MONGODB_URL')

    # Create a new client and connect to the server
    client = MongoClient(uri)

    # Send a ping to confirm a successful connection
    try:
        client.admin.command('ping')
        db = client.iotexample
        print("Pinged your deployment. You successfully connected to MongoDB!")

        app.run(port=5000)

    except Exception as e:
        print(e)
