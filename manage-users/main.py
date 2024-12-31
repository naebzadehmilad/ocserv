from flask_cors import CORS
import random
import string
import os
import logging
import subprocess
# import crypt
from flask import g , Response
import time
import jwt
import requests
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from services.services import *
from config.utils import *

app = Flask(__name__)


CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})


#####################auth
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
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        is_valid, result = validate_token(token)
        if is_valid:
            g.user = result['user']
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

##################


@app.route('/login', methods=['POST'])
def login():

    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'password',
        'username': username,
        'password': password
    }

    response = requests.post(token_url, data=data)

    if response.status_code != 200:
        return jsonify({"error": "Invalid credentials"}), 401

    token_data = response.json()
    log_event('info',f'Access by: {username}')
    return jsonify(token_data), 200


@app.route('/refreshtoken', methods=['POST'])
def refresh_token():

    refresh_token = request.json.get('refresh_token')

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }

    response = requests.post(token_url, data=data)

    if response.status_code != 200:
        return jsonify({"error": "Invalid refresh token"}), 401

    token_data = response.json()
    log_event('info',f'Access by refresh token : {refresh_token}')
    return jsonify(token_data), 200

@app.route('/userdel-bulk', methods=['POST'])
def userdel_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Invalid file format. Only .txt files are allowed."}), 400

    lines = file.read().decode('utf-8').splitlines()
    result = []

    for line in lines:
        parts = line.strip().split(',')
        username = parts[0]

        if username in RESERVE:
            return jsonify({"error": f"User {username} is in the reserve list, cannot delete."}), 400

        if username:
            user_info = delete_user(username)
            result.append(user_info)

    return jsonify(result), 200



@app.route('/useradd-bulk', methods=['POST'])
def useradd_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Invalid file format. Only .txt files are allowed."}), 400

    try:
        lines = file.read().decode('utf-8').splitlines()
    except Exception as e:
        return jsonify({"error": f"Error reading file: {str(e)}"}), 400

    result = []

    for line in lines:
        parts = line.strip().split(',')
        if len(parts) == 2:
            username = parts[0].strip()
            mobile = parts[1].strip()

            if not username or not mobile:
                result.append({"error": f"Invalid data for line: '{line}'"})
                continue

            file_path = f'/home/{username}/mobile.txt'

            try:
                user_info = create_user(username)
                with open(file_path, 'w') as file:
                    file.write(f'{mobile}')

                result.append(user_info)
                result.append(f"Mobile saved to {file_path}")
            except Exception as e:
                result.append({"error": f"Failed to process user '{username}': {str(e)}"})
        else:
            result.append({"error": f"Invalid line format: '{line}'"})

    return jsonify(result), 200


@app.route('/passwordupdate-bulk', methods=['POST'])

def password_update_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Invalid file format. Only .txt files are allowed."}), 400

    lines = file.read().decode('utf-8').splitlines()
    result = []
    for line in lines:
        parts = line.strip().split(',')
        username = parts[0]

        if username in RESERVE:
            return jsonify({"error": f"User {username} is in the reserve list, cannot delete."}), 400

        if username:
            user_info = update_password(username)
            result.append(user_info)

    return jsonify(result), 200

@app.route('/googleauthupdate-bulk', methods=['POST'])
def googleauth_update_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Invalid file format. Only .txt files are allowed."}), 400

    lines = file.read().decode('utf-8').splitlines()
    result = []
    for line in lines:
        parts = line.strip().split(',')
        username = parts[0]

        if username in RESERVE:
            return jsonify({"error": f"User {username} is in the reserve list, cannot delete."}), 400

        if username:
            user_info = update_google_auth(username)
            result.append(user_info)

    return jsonify(result), 200


@app.route('/passwordupdate', methods=['POST'])
def p_update_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    data = request.get_json()

    if 'username' not in data and 'password' not in data  :
        return jsonify({"error": "Missing 'username' and 'password' in the request."}), 400

    username = data['username']
    password = data['password']

    if username in RESERVE:
        return jsonify({"error": f"User {username} is in the reserve list, cannot delete."}), 400
    result = []
    if username and password:
            user_info = update_password_custom(username,password)
            result.append(user_info)

    return jsonify(result), 200

@app.route('/deleteuser', methods=['POST'])
def d_user_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    data = request.get_json()

    if 'username' not in data :
        return jsonify({"error": "Missing 'username' or 'password' in the request."}), 400

    username = data['username']

    if username in RESERVE:
        return jsonify({"error": f"User {username} is in the reserve list, cannot delete."}), 400

    response = delete_user(username)

    if "error" in response:
        print(response["details"])
        return jsonify(response), 500

    return jsonify(response), 200

@app.route('/createuser', methods=['POST'])
def c_user_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    data = request.get_json()

    if 'username' not in data or 'password' not in data or 'mobile' not in data:
        return jsonify({"error": "Missing 'username', 'password', or 'mobile' in the request."}), 400

    username = data['username']
    password = data['password']
    mobile = data['mobile']

    try:
        if len(password) < 6:
            raise ValueError("Password must be minimum 6 characters long")
        if len(mobile) < 11 or not mobile.isdigit():
            raise ValueError("Invalid mobile number")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    response = c_user(username, password, mobile)

    if "error" in response:
        print(response["details"])
        return jsonify(response), 500

    return jsonify(response), 200

@app.route('/passwordgenerator', methods=['GET'])
def generate_password_endpoint():
    k = request.args.get('k')

    if not k:
        return jsonify({"error": "The 'k' parameter (password length) is required."}), 400

    try:
        k = int(k)
        if k <= 0:
            raise ValueError("Password length must be greater than zero.")
        if k > 30:
            raise ValueError("Password length Error")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    password = password_generator(k)
    return jsonify({"password": password}), 200


@app.route('/create-mobile', methods=['POST'])
def create_mobile_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    data = request.get_json()
    username = data.get('username')
    mobile = data.get('mobile')

    if not username or not mobile:
        return jsonify({"error": "Both 'username' and 'mobile' are required."}), 400

    try:
        if len(mobile) < 11:
            raise ValueError("mobile must be maximum 11 characters long")

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    result = c_mobile(username, mobile)

    if "success" in result:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@app.route('/ocserv-logs', methods=['GET'])
def ocserv_logs_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    logs = get_ocserv_logs()
    if "error" in logs:
        return jsonify(logs), 500
    return jsonify(logs), 200


@app.route('/users', methods=['GET'])
def users_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    users = show_users()
    return jsonify({"users": users})

@app.route('/login-users', methods=['GET'])
def login_users_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    login_users = show_login_users()

    return login_users, 200, {'Content-Type': 'application/json'}

@app.route('/show-status', methods=['GET'])
def show_status():
    if AUTH.lower() == 'true':
        auth_response = protect_func()
        if auth_response:
            return auth_response

    status = show_status()
    if not status:
        return jsonify({"error": "Failed to fetch status"}), 500

    return jsonify({"status": status})



@app.route('/show-all-sessions', methods=['GET'])
def show_sessions():
    if AUTH.lower() == 'true':
        auth_response = protect_func()
        if auth_response:
            return auth_response

    status = show_all_sessions()

    return status, 200, {'Content-Type': 'application/json'}

@app.route('/session-info', methods=['GET'])
def info_session():
    if AUTH.lower() == 'true':
        auth_response = protect_func()
        if auth_response:
            return auth_response
    session_id = request.args.get('session_id')

    session_data = session_info(session_id)

    return session_data, 200, {'Content-Type': 'application/json'}



@app.route('/test-sms', methods=['POST'])
def send_sms():
    if AUTH.lower() == 'true':
        auth_response = protect_func()
        if auth_response:
            return auth_response

    data = request.get_json()

    if 'username' not in data:
        return jsonify({"error": "Missing 'username' in the request."}), 400

    username = data['username']

    try:
        sms_script = f'/home/{username}/sms.sh'

        if not os.path.exists(sms_script):
            return jsonify({"error": f"SMS script for user {username} not found."}), 404

        env = os.environ.copy()
        env["PAM_USER"] = username

        subprocess.Popen([sms_script], env=env)

        return jsonify({
            "message": f"SMS task initiated for user {username}. The script is running in the background."
        }), 200
    except Exception as e:
        return jsonify({
            "error": "Failed to execute SMS script",
            "details": str(e)
        }), 500


@app.route('/start_iftop', methods=['GET'])
def start_iftop():
    if AUTH.lower() == 'true':
        auth_response = protect_func()
        if auth_response:
            return auth_response

    interface = request.args.get('interface', 'tun0')
    if not interface:
        return jsonify({"error": "No interface ."}), 400

    if interface in ['ens160', 'ens192' ,'ens224' ]:
        return jsonify({"error": f"Invalid interface: {interface}"}), 400


    return generate_iftop(interface)

    return Response(generate(), content_type='text/event-stream')


@app.route('/ping', methods=['GET'])
def ping_route():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP parameter is required"}), 400

    result = ping(ip)
    return jsonify({"result": result})

@app.route('/check-port', methods=['GET'])
def check_port_route():
    port = request.args.get('port')
    ip = request.args.get('ip')
    protocol = request.args.get('protocol', 'tcp')

    if not port or not ip:
        return jsonify({"result": "Error: 'port' or 'ip' not provided"}), 400

    port = int(port)
    if port < 1 or port > 65535:
        return jsonify({"result": "Error: 'port' not valid"}), 400

    result = check_port(port, ip, protocol)

    return jsonify({"result": result})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify(status='healthy'), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
