#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

#spray.py:
apt-get install -y python3-winrm python3-paramiko

#Skeletor:
apt-get install -y \
    python3-flask \
    python3-flask-sqlalchemy \
    python3-requests \
    python3-dotenv \
    python3-psycopg2 \
    gunicorn