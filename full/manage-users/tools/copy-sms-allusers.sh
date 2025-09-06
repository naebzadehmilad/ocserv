#!/bin/bash

sms_script="./sms.sh"

for home_dir in /home/*; do
    if [ -d "$home_dir" ]; then
        cp "$sms_script" "$home_dir/sms.sh"
        chmod 755 "$home_dir/sms.sh"
    fi
done
