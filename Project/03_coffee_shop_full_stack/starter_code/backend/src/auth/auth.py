import json
from flask import request, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen
from dotenv import dotenv_values

config = dotenv_values('.env')

AUTH0_DOMAIN = config['AUTH0_DOMAIN']
API_AUDIENCE = config['API_AUDIENCE']
ALGORITHMS = ['RS256']

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    """Get token from Authorization header

    Returns:
        str: Token
    """
    # check if authorization is not in request
    if 'Authorization' not in request.headers:
        abort(401)
    # get the token
    auth_header = request.headers['Authorization']
    header_parts = auth_header.split(' ')
    # check if token is valid
    if len(header_parts) != 2:
        abort(401)
    elif header_parts[0].lower() != 'bearer':
        abort(401)
    return header_parts[1]


def check_permissions(permission, payload):
    """Check if a permission is in payload

    Args:
        permission (str): Permission
        payload (str): Payload

    Raises:
        AuthError: Auth error

    Returns:
        bool: If permission is valid.
    """
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)
    return True


def verify_decode_jwt(token: str):
    """Verify and decode payload of jwt token

    Args:
        token (str): Token to be verified

    Raises:
        AuthError: Auth error
    """
    token = get_token_auth_header()
    jsonurl = urlopen(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer="https://" + AUTH0_DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                "please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload

    raise AuthError({"code": "invalid_header",
                    "description": "Unable to find appropriate key"}, 401)


def requires_auth(permission=''):
    """Required auto decorator

    Args:
        permission (str, optional): Permission. Defaults to ''.
    """
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(*args, **kwargs)

        return wrapper
    return requires_auth_decorator
