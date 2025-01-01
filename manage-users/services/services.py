import random
import string
import os
import subprocess
import crypt
from flask import Flask, request, jsonify
import time
import json

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
            ["occtl", "--json", "show", "users"],
            check=True,
            text=True,
            capture_output=True
        )

        if not result.stdout.strip():
            print("Command succeeded but returned empty output.")
            return None

        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON: {e}")
#        return json.loads(result.stdout.strip())
#    except subprocess.CalledProcessError as e:
#        print(f"Command failed with error: {e.stderr}")
#    except json.JSONDecodeError as e:
#        print(f"Failed to parse JSON: {e}")

def show_status():
    try:
        result = subprocess.run(
            ["occtl", "show", "status"],
            check=True,
            text=True,
            capture_output=True
        )
        return result.stdout.strip().split("\n")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return []


def show_all_sessions():
    command = "occtl show sessions all"
    output = subprocess.check_output(command, shell=True, text=True)
    
    lines = output.strip().split('\n')[1:]
    
    sessions = []
    
    for line in lines:
        parts = line.split()
        
        session = parts[0]
        user = parts[1]
        vhost = parts[2]
        ip = parts[3]
        
        user_agent = " ".join(parts[4:-2])  
        created = parts[-2]
        status = parts[-1]
        
        session_dict = {
            "session": session,
            "user": user,
            "vhost": vhost,
            "ip": ip,
            "user_agent": user_agent,
            "created": created,
            "status": status
        }
        
        sessions.append(session_dict)
    
    json_data = json.dumps({"sessions": sessions}, indent=2)
    return json_data

def get_ocserv_logs():
    try:
        result = subprocess.run(
            ["journalctl", "-u", "ocserv", "-n", "100", "--no-pager"],
            check=True,
            text=True,
            capture_output=True
        )
        logs = result.stdout.strip().split("\n")
        return {"logs": logs}
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to fetch logs: {e}"}

def c_user(username, password, mobile):
    try:
        print(f"Creating user {username} with password: {password} and mobile: {mobile}")

        user_home = f'/home/{username}'
        google_auth_file = f'{user_home}/.google_authenticator'
        mobile_file = f'{user_home}/mobile.txt'

        subprocess.run(['/usr/sbin/useradd', '-m', '-s', '/usr/sbin/nologin', username], check=True)

        hashed_password = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
        subprocess.run(['/usr/sbin/usermod', '--password', hashed_password, username], check=True)

        subprocess.run(
            ['google-authenticator', '-t', '-d', '-f', '-u', '-w', '5', '-C', '-s', google_auth_file],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )

        subprocess.run(['chown', f'{username}:{username}', google_auth_file], check=True)
        subprocess.run(['chmod', '600', google_auth_file], check=True)

        if os.path.exists(mobile_file):
            os.remove(mobile_file)  
        with open(mobile_file, 'w') as f:
            f.write(mobile)

        subprocess.run(['chown', f'{username}:{username}', mobile_file], check=True)
        subprocess.run(['chmod', '600', mobile_file], check=True)

        subprocess.run(['chmod', '666', '/dev/net/tun'], check=True)

        with open(google_auth_file, 'r') as file:
            google_auth = file.read()

        return {
            "username": username,
            "password": password,
            "mobile": mobile,
            "google_auth": google_auth,
            "message": f"User {username} created successfully with password {password} and mobile number {mobile}."
        }
    except Exception as e:
        return {"error": "Failed to create user", "details": str(e)}


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

def update_password_custom(username,password):
    try:
        if not user_exists(username):
            return {"error": f"User {username} not exists."}

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


def generate_iftop(interface):
    try:
        process = subprocess.Popen(
            ["sudo", "iftop", "-i", interface, "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            if line:
                ###Genearte yield
                yield f"data: {line.strip()}\n\n"
                time.sleep(0.7)  
    except Exception as e:
        yield f"data: Error: {str(e)}\n\n"
    finally:
        process.terminate() 

def ping(ip):
    try:
        process = subprocess.Popen(
            ["ping", "-c", "2", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            return stdout 
        else:
            return f"Error: {stderr}" 
    except Exception as e:
        return f"Exception occurred: {str(e)}"

def check_port(port, ip, protocol='tcp'):
    try:
        port = str(port)
        ip = str(ip)

        if protocol == 'udp':
            command = ["nc", "-v", "-z", "-u", "-w", "2", ip, port]
        else:
            command = ["nc", "-v", "-z", "-w", "2", ip, port]

        print(f"Running command: {' '.join(command)}")  

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = process.communicate()

        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}") 

        if process.returncode == 0:
            return f"Connection to {ip} {port} succeeded!"
        else:
            return f"Error: {stderr}"

    except Exception as e:
        return f"Exception occurred: {str(e)}"
