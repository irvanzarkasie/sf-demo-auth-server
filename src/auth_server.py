import sys
import json
from flask import Flask, request, jsonify, make_response, Response
import pprint
import logging
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
import uuid
import socket
from datetime import datetime, timedelta
import os
import jwt
from cryptography.x509 import load_pem_x509_certificate

app = Flask(__name__)

# CONSTANTS
api_host = socket.gethostname()
api_port = 34110
api_id = "auth_server"
CERTKEY_1 = "323b214ae6975a0f034ea77354dc0c25d03642dc"
CERTKEY_2 = "a3b762f871cdb3bae0044c649622fc1396eda3e3"
AUTH_CERTS = {
    CERTKEY_1: CERTKEY_1,
    CERTKEY_2: CERTKEY_2
}
VALID_CLIENT_ID = set(["8373854997-of44d9n5qupldqhlc5hh9h99d2q6rfk5.apps.googleusercontent.com"])

# Work directory setup
script_dir = os.path.dirname(os.path.realpath(__file__))
home_dir = "/".join(script_dir.split("/")[:-1])
log_dir = "{home_dir}/logs".format(home_dir=home_dir)

@app.route('/auth/certs', methods=['GET'])
def get_auth_certs():
  return jsonify(AUTH_CERTS)
# end def

@app.route('/auth/exchange_token', methods=['GET'])
def do_auth_exchange():
  TTL = 600
  EXCHANGETS = int(datetime.now().timestamp())
  EXCHANGEEXP = EXCHANGETS + TTL
  EXCHANGECERT_KEY = CERTKEY_2
  
  # Parse arguments
  args = request.args
  client_id = args.get("client_id", "")

  if client_id not in VALID_CLIENT_ID:
    return jsonify({"status_code": 401, "status_desc": "Invalid client_id"}), 401
  # end if

  auth_payload = {
    "client_id": client_id,
    "auth_key": EXCHANGECERT_KEY,
    "expired_time": EXCHANGEEXP
  }
  auth_secret = EXCHANGECERT_KEY
  
  return jsonify({"status_code": 200, "status_desc": "Success", "token": jwt.encode(payload=auth_payload, key=auth_secret)})
# end def

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=api_port)
# end if
