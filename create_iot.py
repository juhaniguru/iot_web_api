import os

from bson import ObjectId
from dotenv import load_dotenv
from passlib.context import CryptContext
from pymongo import MongoClient

from iot_token import AsymmetricToken

if __name__ == '__main__':

    bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

    load_dotenv()
    uri = os.getenv('MONGODB_URL')

    # Create a new client and connect to the server
    client = MongoClient(uri)

    # Send a ping to confirm a successful connection
    try:
        client.admin.command('ping')
        db = client.iotexalkjmple

        print("Pinged your deployment. You successfully connected to MongoDB!")

        username = input("Give iot username:")
        pwd = input("Give password: ")

        iot_user_dic = {'username': username, 'password': bcrypt_context.hash(pwd), 'role': 'iot'}
        db.users.insert_one(iot_user_dic)

        user = db.users.find_one({'_id': iot_user_dic['_id']})
        _token = AsymmetricToken()
        access_token = _token.create(
        {'type': 'access', 'role': user['role'], 'exp': None, 'sub': str(user['_id']), 'csrf': None})
        print(access_token)


    except Exception as e:
        print(e)
