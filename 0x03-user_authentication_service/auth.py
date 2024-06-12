#!/usr/bin/env python3
'''auth module'''
import uuid
import bcrypt
from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    '''returned bytes is a salted hash of the input password'''
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """add new user to DB
        """

        user = self._db.find_user_by(email=email)
        if user:
            raise ValueError('User {} already exists'.format(email))
        else:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """check if a user is valid
        """
        user = self._db.find_user_by(email=email)
        if user and bcrypt.checkpw(password.encode('utf-8'),
                                   user.hashed_password):
            return True
        return False

    def _generate_uuid(self) -> str:
        '''generate a uuid'''
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        '''create a session for a user'''
        user = self._db.find_user_by(email=email)
        if user:
            session_id = self._generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        return None

    def get_user_from_session_id(self, session_id: str) -> User | None:
        '''get user from session id'''
        if not session_id:
            return None
        user = self._db.find_user_by(session_id=session_id)
        if user is None:
            return None
        return user

    def destroy_session(self, session_id: str) -> None:
        '''destroy session'''
        user = self._db.find_user_by(session_id=session_id)
        if user:
            self._db.update_user(user.id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        '''get reset password token'''
        user = self._db.find_user_by(email=email)
        if user:
            reset_token = self._generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        '''update password'''
        user = self._db.find_user_by(reset_token=reset_token)
        if user:
            hashed_password = _hash_password(password)
            self._db.update_user(user.id,
                                 hashed_password=hashed_password,
                                 reset_token=None)
        raise ValueError
