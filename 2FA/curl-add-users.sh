curl -X POST http://127.0.0.1:5000/useradd \
     -F "file=@users_add.txt" \
     -H "Content-Type: multipart/form-data"

###echo -e "m1\nm2\nm3" > "users_add.txt"
