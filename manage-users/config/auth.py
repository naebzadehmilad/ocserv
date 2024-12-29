import logging
import os

RESERVE = ['naebzadeh', 'root', 'a.shamsi', 'm.shahbazi', 's.rostami', 'mn']

AUTH = 'TRUE'

PORT_APP = 5000
########auth-jwt
KEYCLOAK_URL = 'https://auth-management.zap-devops.ir'
REALM_NAME = 'ocserv'
CLIENT_ID = 'ocserv'
CLIENT_SECRET = 'qqetYXW5tYP2CFVe87ckYVzoZP2CmA0d'
AUDIENCE = CLIENT_ID
# Logging setup
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s')

def log_event(level, message):
    if level == 'info':
        logging.info(message)
    elif level == 'error':
        logging.error(message)


