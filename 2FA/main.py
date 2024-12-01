import random
import string
import os
import subprocess
import crypt
from flask import Flask, request, jsonify

app = Flask(__name__)

def generate_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def create_user(username):
    try:
        password = generate_password()
        print(username,password)

        subprocess.run(['useradd', '-m', '-s', '/usr/sbin/nologin', username] ,check=True)


        hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))

        subprocess.run(['usermod', '--password', hashed_password, username], check=True)

        

        user_home = f'/home/{username}'


        result = subprocess.run(
            ['google-authenticator', '-t', '-d', '-f', '-u', '-w', '3', '-C', '-s', f'{user_home}/.google_authenticator'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )

        google_auth = None
        
        subprocess.run(['chown', f'{username}:{username}', f'{user_home}/.google_authenticator'], check=True)

        subprocess.run(['chmod', '600', f'{user_home}/.google_authenticator'], check=True)

        subprocess.run(['chmod','666','/dev/net/tun'], check=True)

        with open(f'{user_home}/.google_authenticator', 'r') as file:
            google_auth = file.read()

        return {
            "username": username,
            "password": password,
            "google_auth": google_auth,
            "message": f"User {username} created successfully with password {password} and Google Authenticator set up."
        }





    except subprocess.CalledProcessError as e:
        return {"error": f"Error creating user {username}: {e}"}

def delete_user(username):
    try:
        subprocess.run(['userdel', '-r', username], check=True)
        return {"username": username, "message": "User deleted successfully."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Error deleting user {username}: {e}"}

@app.route('/userdel', methods=['POST'])
def userdel_endpoint():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Invalid file format. Only .txt files are allowed."}), 400

    lines = file.read().decode('utf-8').splitlines()
    result = []

    for line in lines:
        username = line.strip()

        if username:
            user_info = delete_user(username)
            result.append(user_info)

    return jsonify(result), 200

@app.route('/useradd', methods=['POST'])
def useradd_endpoint():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Invalid file format. Only .txt files are allowed."}), 400

    lines = file.read().decode('utf-8').splitlines()
    result = []

    for line in lines:
        username = line.strip()

        if username:
            user_info = create_user(username)
            result.append(user_info)

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True)