#!/usr/bin/env python3
"""module of the authetication of API
"""
from typing import List
from typing import TypeVar as TV
import re
from flask import request


class Auth:
    """ class for authenticating
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """method to see authentication is needed for a path
        """
        tof = False
        if path is not None and excluded_paths is not None:
            for exclude_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclude_path[-1] == '*':
                    pattern = '{}.*'.format(exclude_path[0:-1])
                elif exclude_path[-1] == '/':
                    pattern = '{}/*'.format(exclude_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclude_path)
                if re.match(pattern, path):
                    return tof
        tof = True
        return tof

    def authorization_header(self, request=None) -> str:
        """ method to get authorization header from the request
        """
        if request is not None:
            request_header = request.headers.get('Authorization', None)
            return request_header
        return None

    def current_user(self, request=None) -> TV('User'):
        """method to get current users using request
        """
        return None
