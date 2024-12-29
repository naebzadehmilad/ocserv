import random
import string
import os
import subprocess
import crypt
from flask import Flask, request, jsonify
from auth.auth import *
from services.services import *


app = Flask(__name__)




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


@app.route('/createuser', methods=['POST'])
def c_user_endpoint():
    if AUTH.lower() == 'true':
        if protect_func():
            return protect_func()

    data = request.get_json()

    if 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing 'username' or 'password' in the request."}), 400

    username = data['username']
    password = data['password']

    response = c_user(username, password)

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
    return jsonify({"login_users": login_users})



if __name__ == '__main__':
    app.run(debug=True)
