import os

from dotenv import load_dotenv
from passlib.context import CryptContext
from pymongo import MongoClient


if __name__ == '__main__':

    bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

    load_dotenv()
    uri = os.getenv('MONGODB_URL')

    # Create a new client and connect to the server
    client = MongoClient(uri)



    # Send a ping to confirm a successful connection
    try:
        client.admin.command('ping')
        db = client.iotexample



        print("Pinged your deployment. You successfully connected to MongoDB!")

        username = input("Give admin username:")
        pwd = input("Give password: ")

        db.users.insert_one({'username': username, 'password': bcrypt_context.hash(pwd), 'role': 'admin'})


    except Exception as e:
        print(e)