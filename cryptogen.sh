#!/bin/sh
cd /usr/share/easy-rsa

./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa build-server-full $LS_SERVERNAME nopass
./easyrsa build-client-full $LS_CLIENTNAME nopass

export CA_CERT=/usr/share/easy-rsa/pki/ca.crt
export SERVER_CERT=/usr/share/easy-rsa/pki/issued/$LS_SERVERNAME.crt
export SERVER_KEY=/usr/share/easy-rsa/pki/private/$LS_SERVERNAME.key
export CLIENT_CERT=/usr/share/easy-rsa/pki/issued/$LS_CLIENTNAME.crt
export CLIENT_KEY=/usr/share/easy-rsa/pki/private/$LS_CLIENTNAME.key

cd /app/sitch
python ./cryptoload.py
