#/bin/sh/
#generating alice key with public exponent 3
openssl genpkey -algorithm RSA -out alice.pem -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3
openssl rsa -in alice.pem -RSAPublicKey_out -out alice.pub
openssl rsa -pubin -inform PEM -text -noout <  alice.pub

fuser 5005/tcp -k
python3 bob.py $1 &
sleep 3 
python3 oscar.py
