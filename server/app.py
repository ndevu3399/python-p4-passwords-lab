#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        password_confirmation = json.get('password_confirmation', password)

        if not username or not password:
            return {'error': 'Username and password required'}, 400

        if password != password_confirmation:
            return {'error': 'Passwords do not match'}, 422

        if User.query.filter_by(username=username).first():
            return {'error': 'Username already taken'}, 422

        user = User(username=username)
        user.password_hash = password  # Uses setter

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

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

# Routes
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
