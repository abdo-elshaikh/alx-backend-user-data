#!/usr/bin/env python3
'''app module'''
from flask import Flask, jsonify, redirect, request, abort
from auth import Auth

app = Flask(__name__)
AUTH = Auth()
app.url_map.strict_slashes = False


@app.route('/', methods=['GET'])
def index():
    '''index page'''
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    '''users page'''
    email = request.form['email']
    password = request.form['password']

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError as e:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    '''sessions page'''
    email = request.form['email']
    password = request.form['password']

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if session_id:
            response = jsonify({"email": email, "message": "logged in"})
            response.set_cookie("session_id", session_id)
            return response
    return abort(401)


@app.route('/sessions', methods=['DELETE'])
def logout():
    '''sessions page'''
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect('/')
    return abort(403)


@app.route('/profile', methods=['GET'])
def profile():
    '''profile page'''
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    return abort(403)


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    '''reset password'''
    email = request.form['email']

    if email:
        token = AUTH.get_reset_password_token(email)
        if token:
            return jsonify({"email": email, "reset_token": token}), 200
    return abort(403)


@app.route('/reset_password', methods=['POST'])
def update_password():
    '''update password'''
    email = request.form['email']
    reset_token = request.form['reset_token']
    new_password = request.form['new_password']

    if email and reset_token and new_password:
        try:
            AUTH.update_password(reset_token, new_password)
            return jsonify(
                {"email": email, "message": "Password updated"}), 200
        except ValueError:
            return abort(403)
    return abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
