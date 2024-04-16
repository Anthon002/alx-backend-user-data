#!/usr/bin/env python3
"""module for authentication for the API
"""
import base64 as b64_
import re
import binascii
from typing import Tuple, TypeVar

from models.user import User
from .auth import Auth


class BasicAuth(Auth):
    """ authentication class
    """
    def extract_b64__authorization_header(
            self,
            authorization_header: str) -> str:
        """method to extract base64 from the auth header
        """
        if type(authorization_header) == str:
            format_ = r'Basic (?P<token>.+)'
            matching_filed = re.fullmatch(format_, authorization_header.strip())
            if matching_filed is not None:
                match_ = matching_filed.group('token')
                return match_
        return None

    def decode_b64__authorization_header(
            self,
            b64__authorization_header: str,
            ) -> str:
        """method ot decoded the b64_ encoded header
        """
        if type(b64__authorization_header) == str:
            try:
                res = b64_.b64decode(
                    b64__authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_b64__authorization_header: str,
            ) -> Tuple[str, str]:
        """method to get user info from the base64 decoded header
        """
        if type(decoded_b64__authorization_header) == str:
            format_ = r'(?P<user>[^:]+):(?P<password>.+)'
            matching_filed = re.fullmatch(
                format_,
                decoded_b64__authorization_header.strip(),
            )
            if matching_filed is not None:
                user = matching_filed.group('user')
                password = matching_filed.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """ method to get users using their credentials.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                user = users[0]
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """method to get user from requests
        """
        header_ = self.authorization_header(request)
        b64_authentication_token = self.extract_b64__authorization_header(header_)
        authentication_token = self.decode_b64__authorization_header(b64_authentication_token)
        email, password = self.extract_user_credentials(authentication_token)
        return self.user_object_from_credentials(email, password)
