#!/bin/bash

USER_SCRIPT="/home/$PAM_USER/sms.sh"

if [ -f "$USER_SCRIPT" ]; then
    exec "$USER_SCRIPT"
    exit 1
else
    echo "Script for user $PAM_USER not found at $USER_SCRIPT" >&2
    exit 1
fi
