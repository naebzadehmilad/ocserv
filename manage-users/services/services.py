import random
import string
import os
import subprocess
import crypt
from flask import Flask, request, jsonify

app = Flask(__name__)

def generate_password():
    k=8
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

def password_generator(k):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=k))

def user_exists(username):
    try:
        subprocess.run(['id', username], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False



def show_users():
    try:
        result = subprocess.run(
            "awk -F: '$3 > 1000 {print $1,       $7}' /etc/passwd  ",
            shell=True,
            check=True,
            text=True,
            capture_output=True
        )
        return result.stdout.strip().split("\n")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []

def show_login_users():
    try:
        result = subprocess.run(
            "occtl show users",
            shell=True,
            check=True,
            text=True,
            capture_output=True
        )
        return result.stdout.strip().split("\n")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []


def c_user(username, password):
    try:
        print(f"Creating user {username} with password: {password}")

        user_home = f'/home/{username}'
        google_auth_file = f'{user_home}/.google_authenticator'

        subprocess.run(['/usr/sbin/useradd', '-m', '-s', '/usr/sbin/nologin', username], check=True)

        hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        subprocess.run(['/usr/sbin/usermod', '--password', hashed_password, username], check=True)

        subprocess.run(
            ['google-authenticator', '-t', '-d', '-f', '-u', '-w', '5', '-C', '-s', google_auth_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )

        subprocess.run(['chown', f'{username}:{username}', google_auth_file], check=True)
        subprocess.run(['chmod', '600', google_auth_file], check=True)
        subprocess.run(['chmod', '666', '/dev/net/tun'], check=True)

        with open(google_auth_file, 'r') as file:
            google_auth = file.read()

        return {
            "username": username,
            "password": password,
            "google_auth": google_auth,
            "message": f"User {username} created successfully with password {password} and Google Authenticator set up."
        }

    except subprocess.CalledProcessError as e:
        error_message = f"Command failed: {e.cmd}\nReturn code: {e.returncode}\nOutput: {e.stderr}"
        print(error_message)
        return {
            "error": f"Failed to execute a command.",
            "details": error_message
        }
    except Exception as e:
        error_message = f"An unexpected error occurred: {str(e)}"
        print(error_message)
        return {
            "error": "An unexpected error occurred.",
            "details": error_message
        }


def create_user(username):
    try:
        password = generate_password()
        print(username,password)
        user_home = f'/home/{username}'
        google_auth_file = f'{user_home}/.google_authenticator'

        subprocess.run(['/usr/sbin/useradd', '-m', '-s', '/usr/sbin/nologin', username] ,check=True)


        hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))

        subprocess.run(['/usr/sbin/usermod', '--password', hashed_password, username], check=True)



        user_home = f'/home/{username}'


        subprocess.run(
            ['google-authenticator', '-t', '-d', '-f', '-u', '-w', '5','-C', '-s', google_auth_file],
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
            ['google-authenticator', '-t', '-d', '-f', '-u', '-w', '5','-C', '-s', google_auth_file],
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
