#!/usr/bin/env python3
import requests
import requests.cookies

url = 'http://0.0.0.0:5000'


def register_user(email: str, password: str) -> None:
    """Register a new user"""
    data = {'email': email, 'password': password}
    response = requests.post(f'{url}/users', data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'user created'}
    response = requests.post(f'{url}/users', data=data)
    assert response.status_code == 400
    assert response.json() == {'message': 'email already registered'}


def log_in_wrong_password(email: str, password: str) -> None:
    """Log in a user with wrong password"""
    data = {'email': email, 'password': password}
    response = requests.post(f'{url}/sessions', data=data)
    assert response.status_code == 401
    assert response.cookies.get('session_id') is None


def log_in(email: str, password: str) -> str:
    """Log in a user"""
    data = {'email': email, 'password': password}
    response = requests.post(f'{url}/sessions', data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'logged in'}
    session_id = response.cookies.get('session_id')
    assert session_id is not None
    return session_id


def profile_unlogged() -> None:
    """Profile of an unlogged user"""
    response = requests.get(f'{url}/profile')
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Profile of a logged user"""
    response = requests.get(f'{url}/profile',
                            cookies={'session_id': session_id})
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """Log out a user"""
    response = requests.delete(f'{url}/sessions',
                               cookies={'session_id': session_id})
    # print(response.status_code)
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """Get reset password token"""
    data = {'email': email}
    response = requests.post(f'{url}/reset_password', data=data)
    assert response.status_code == 200
    assert response.json()['email'] == email
    reset_token = response.json()['reset_token']
    assert reset_token is not None
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update password"""
    data = {
        'email': email,
        'reset_token': reset_token,
        'new_password': new_password
        }
    response = requests.post(f'{url}/reset_password', data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'Password updated'}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    session_id = log_in(EMAIL, NEW_PASSWD)
    profile_logged(session_id)
    log_out(session_id)
