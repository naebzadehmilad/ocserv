#!/bin/bash

if [ "$PAM_TYPE" == "close_session" ]; then
    # Log or clean up resources here
    logger "Session closed for user $PAM_USER"
fi

#chmod 0644 /$USER/.google_authenticator
#chown $USER:$USER ~/.google_authenticator

USER_SCRIPT="/home/$PAM_USER/sms.sh"
#loginctl terminate-user $PAM_USER
if [ -f "$USER_SCRIPT" ]; then
    exec "$USER_SCRIPT"
    exit 1
else
    echo "Script for user $PAM_USER not found at $USER_SCRIPT" >&2
    exit 1
fi
