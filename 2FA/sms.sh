#!/bin/bash
USER_HOME="/home/$PAM_USER/.google_authenticator"
LOCK_FILE="/home/$PAM_USER/sms.lock"
SLEEP_DURATION=${SLEEP_DURATION:-60}
SECRET=$(head -n 1 "$USER_HOME")
OTP=$(oathtool --totp -b "$SECRET")
API_KEY="959352B53656875744414F32453"
NUMBER="0912289"

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

#/etc/skel/sms.sh
