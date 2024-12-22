import random
import string
import os
import subprocess
import crypt
from flask import Flask, request, jsonify

app = Flask(__name__)

def generate_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

def user_exists(username):
    try:
        subprocess.run(['id', username], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False


def create_user(username):
    try:
        password = generate_password()
        print(username,password)

        subprocess.run(['/usr/sbin/useradd', '-m', '-s', '/usr/sbin/nologin', username] ,check=True)


        hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))

        subprocess.run(['/usr/sbin/usermod', '--password', hashed_password, username], check=True)



        user_home = f'/home/{username}'


        result = subprocess.run(
            ['/usr/bin/google-authenticator', '-t', '-d', '-f', '-u', '-w', '3', '-s', f'{user_home}/.google_authenticator'],
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
        if not user_exists(username):
            return {"error": f"User {username} not exists."}

        subprocess.run(['/usr/sbin/userdel', '-r', username], check=True)
        return {"username": username, "message": "User deleted successfully."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Error deleting user {username}: {e}"}

def update_google_auth(username):
    try:
        if not user_exists(username):
            return {"error": f"User {username} Not exists."}

        user_home = f'/home/{username}'
        google_auth_file = f'{user_home}/.google_authenticator'

        subprocess.run(
            ['google-authenticator', '-t', '-d', '-f', '-u', '-w', '3', '-C' , '-s', google_auth_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )

        subprocess.run(['chmod', '600', google_auth_file], check=True)
        subprocess.run(['chown', f'{username}:{username}', google_auth_file], check=True)

        with open(google_auth_file, 'r') as file:
            google_auth = file.read()

        return {
            "username": username,
            "google_auth": google_auth,
            "message": "Google Authenticator updated successfully."
        }
    except subprocess.CalledProcessError as e:
        return {"error": f"Error updating Google Authenticator for {username}: {e}"}

def update_password(username):
    try:
        if not user_exists(username):
            return {"error": f"User {username} not exists."}

        password = generate_password()
        hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        subprocess.run(['/usr/sbin/usermod', '--password', hashed_password, username], check=True)


        user_home = f'/home/{username}'
        google_auth_file = f'{user_home}/.google_authenticator'

        subprocess.run(['chmod','666','/dev/net/tun'], check=True)

        with open(google_auth_file, 'r') as file:
            google_auth = file.read()

        return {
            "username": username,
            "password": password,
            "google_auth": google_auth,
            "message": f"User {username} updated with new password {password}!"
        }
    except subprocess.CalledProcessError as e:
        return {"error": f"Error updating password for {username}: {e}"}

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
        parts = line.strip().split(',')
        username = parts[0]

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


@app.route('/passwordupdate', methods=['POST'])
def password_update_endpoint():
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

        if username:
            user_info = update_password(username)
            result.append(user_info)

    return jsonify(result), 200

@app.route('/googleauthupdate', methods=['POST'])
def googleauth_update_endpoint():
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
        if username:
            user_info = update_google_auth(username)
            result.append(user_info)

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True)
