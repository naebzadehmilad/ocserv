curl -X POST http://127.0.0.1:5000/userdel \
     -F "file=@users_del.txt" \
     -H "Content-Type: multipart/form-data"



###echo -e "m1\nm2\nm3" > "users_del.txt"
