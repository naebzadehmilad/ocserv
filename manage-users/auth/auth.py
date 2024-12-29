import time
import jwt
from flask import request, jsonify, g
import requests
from config.utils import *
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError


jwks = None

def fetch_jwks():
    global jwks
    jwks_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"
    response = requests.get(jwks_url)
    if response.status_code == 200:
        jwks = response.json()
        log_event('info', "JWKS loaded successfully!")
    else:
        log_event('error', f"Failed to fetch JWKS: {response.status_code} - {response.text}")
        exit(1)

fetch_jwks()

def protect_func():
    # fetch token from auth header
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        # validate token
        is_valid, result = validate_token(token)
        if is_valid:
            g.user = result['user']  # Store user information in g object
        else:
            return jsonify({"error": "Unauthorized"}), 401
    else:
        return jsonify({"error": "Authorization header with Bearer token required"}), 401

def fetch_jwks():
    global jwks
    jwks_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"
    response = requests.get(jwks_url)
    if response.status_code == 200:
        jwks = response.json()
        log_event('info',"JWKS loaded successfully!")
    else:
        log_event('error',f"Failed to fetch JWKS: {response.status_code} - {response.text}")


fetch_jwks()




def get_public_key(kid=None):
    global jwks
    if jwks:
        keys = jwks.get('keys')
        if kid:
            for key in keys:
                if key.get('kid') == kid:
                    return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        else:
            # If no kid is provided, return the first key in the JWKS
            if keys:
                return jwt.algorithms.RSAAlgorithm.from_jwk(keys[0])
    return None


def validate_token(token):
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})

        # check expiration time
        if decoded_token.get('exp') and decoded_token['exp'] < int(time.time()):
            return False, {"error": "Token has expired"}

        # check 'not before' time if present
        if decoded_token.get('nbf') and decoded_token['nbf'] > int(time.time()):
            return False, {"error": "Token not yet valid"}

        return True, {"message": "Token is valid", "user": decoded_token}

    except jwt.ExpiredSignatureError:
        return False, {"error": "Token has expired"}

    except jwt.InvalidTokenError:
        return False, {"error": "Invalid token"}
