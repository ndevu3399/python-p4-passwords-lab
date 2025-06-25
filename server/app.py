#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource

from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        password_confirmation = json.get('password_confirmation')

        if password != password_confirmation:
            return {'error': 'Passwords do not match'}, 422

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return {'error': 'Username already taken'}, 422

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(username=username, _password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user._password_hash, password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204

# Routes
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
