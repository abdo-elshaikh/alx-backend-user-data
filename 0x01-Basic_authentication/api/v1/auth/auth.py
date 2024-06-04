#!/usr/bin/env python3
"""api authenication module"""

from flask import request
from typing import List, TypeVar

class Auth:
    """authenticaion class"""
    
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """return False"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != '/':
            path += '/'
        if path in excluded_paths:
            return False
        return True


    def authorization_header(self, request=None) -> str:
        """ Request Flask object """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')


    def current_user(self, request=None) -> TypeVar('User'):
        """return None"""
        return None
