#!/bin/bash
USER_HOME="/home/$PAM_USER/.google_authenticator"
LOCK_FILE="/home/$PAM_USER/sms.lock"
SLEEP_DURATION=${SLEEP_DURATION:-60}
SECRET=$(head -n 1 "$USER_HOME")
OTP=$(oathtool --totp -b "$SECRET")
API_KEY="5959352B5365687574416A"
MOBILE_FILE="/home/$PAM_USER/mobile.txt"
NUMBER=$(cat "$MOBILE_FILE")


if [ -e "$LOCK_FILE" ]; then
    echo "Is Lock.."
    exit 2
fi
touch "$LOCK_FILE"

TOKEN="$OTP"
curl -X POST "https://api.kavenegar.com/v1/$API_KEY/verify/lookup.json" \
    -d "receptor=$NUMBER&template=system&token=$TOKEN"

(
sleep "$SLEEP_DURATION"
rm -f "$LOCK_FILE"
) &
exit 1
#/etc/skel/sms.sh
