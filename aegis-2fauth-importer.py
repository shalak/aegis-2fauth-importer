#!/usr/bin/env python3

import argparse
import base64
import io
import json
import os
import sys
import traceback

import requests
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import cryptography

backend = default_backend()
app = Flask(__name__)

class VaultProcessingError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

def get_env_var(var_name, required=True, default=None):
    value = os.getenv(var_name, default)
    if required and not value:
        raise VaultProcessingError(f"error: {var_name} environment variable not set", 401)
    return value

def get_password(request_pass=None):
    if request_pass:
        return request_pass.encode("utf-8")
    return get_env_var("AEGIS_PASS").encode("utf-8")

def load_vault_from_file(input_path):
    with io.open(input_path, "r") as f:
        return json.load(f)

def load_vault_from_data(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        raise VaultProcessingError("error: invalid JSON input", 400)

def derive_master_key(slots, password):
    for slot in slots:
        kdf = Scrypt(
            salt=bytes.fromhex(slot["salt"]),
            length=32,
            n=slot["n"],
            r=slot["r"],
            p=slot["p"],
            backend=backend
        )
        key = kdf.derive(password)
        cipher = AESGCM(key)
        params = slot["key_params"]
        try:
            return cipher.decrypt(
                nonce=bytes.fromhex(params["nonce"]),
                data=bytes.fromhex(slot["key"]) + bytes.fromhex(params["tag"]),
                associated_data=None
            )
        except cryptography.exceptions.InvalidTag:
            continue
    raise VaultProcessingError("error: unable to decrypt the master key with the given password", 403)

def decrypt_vault(db_content, params, master_key):
    try:
        content = base64.b64decode(db_content)
        cipher = AESGCM(master_key)
        decrypted_db = cipher.decrypt(
            nonce=bytes.fromhex(params["nonce"]),
            data=content + bytes.fromhex(params["tag"]),
            associated_data=None
        ).decode("utf-8")
        return json.loads(decrypted_db)
    except Exception as e:
        raise VaultProcessingError(f"error: failed to decrypt vault - {str(e)}", 500)

def migrate_2fauth(decrypted_db, url, token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {
        "payload": json.dumps({"version": 1, "header": {"slots": None, "params": None}, "db": decrypted_db}),
        "withSecret": True
    }

    try:
        response = requests.post(f"{url}/api/v1/twofaccounts/migration", headers=headers, json=payload)
        if response.status_code != 200:
            raise VaultProcessingError(f"Migration failed: {response.text}", response.status_code)
        return response.json()
    except Exception as e:
        raise VaultProcessingError(f"Migration error: {str(e)}", 500)

def import_to_2fauth(valid_entries, url, token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    report = {"imported": [], "skipped": [], "invalid": [], "errors": []}

    for entry in valid_entries:
        try:
            response = requests.post(f"{url}/api/v1/twofaccounts", headers=headers, json=entry)
            if response.status_code == 201:
                report["imported"].append(f"{entry['service']} - {entry['account']}")
            elif response.status_code == 409:
                report["skipped"].append(f"{entry['service']} - {entry['account']} (already exists)")
            else:
                report["errors"].append({"entry": entry, "error": response.json()})
        except Exception as e:
            report["errors"].append({"entry": entry, "error": str(e)})

    return report

def process_vault(data, password=None, url=None, token=None):
    password = get_password(password)
    url = url or get_env_var("URL_2FAUTH")
    token = token or get_env_var("BEARER_2FAUTH")

    header = data.get("header")
    if not header or "slots" not in header or not isinstance(header["slots"], list):
        raise VaultProcessingError("error: invalid input format. Make sure this is valid, encrypted Aegis backup", 400)

    slots = [slot for slot in header["slots"] if slot["type"] == 1]
    master_key = derive_master_key(slots, password)
    decrypted_db = decrypt_vault(data["db"], header["params"], master_key)

    migration_results = migrate_2fauth(decrypted_db, url, token)
    valid_entries = []

    report = {"imported": [], "skipped": [], "invalid": [], "errors": []}

    for item in migration_results:
        entry_id = item.get("id")
        entry_info = f"{item['service']} - {item['account']} (already exists)"
        if entry_id == 0:
            valid_entries.append(item)
        elif entry_id == -1:
            report["skipped"].append(entry_info)
        elif entry_id == -2:
            report["invalid"].append(entry_info)

    import_report = import_to_2fauth(valid_entries, url, token)
    report["imported"] = import_report["imported"]
    report["skipped"] += import_report["skipped"]
    report["errors"] += import_report["errors"]

    return report

@app.errorhandler(VaultProcessingError)
def handle_vault_processing_error(error):
    response = jsonify({"error": error.message})
    response.status_code = error.status_code
    return response

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]
    if uploaded_file.filename == "":
        return jsonify({"error": "Empty file uploaded"}), 400

    url = request.form.get("url")
    token = request.form.get("token")
    password = request.form.get("password")

    try:
        vault_data = json.load(uploaded_file.stream)
        report = process_vault(vault_data, password=password, url=url, token=token)
        return jsonify(report)
    except VaultProcessingError as e:
        return handle_vault_processing_error(e)
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

def main():
    parser = argparse.ArgumentParser(description="Decrypt an Aegis vault and upload to 2FAuth")
    parser.add_argument("--input", help="encrypted Aegis vault file")
    parser.add_argument("--serve", action="store_true", help="run as Flask server")
    args = parser.parse_args()

    if args.serve:
        app.run(host="0.0.0.0", port=5000)
    elif args.input:
        try:
            data = load_vault_from_file(args.input)
            report = process_vault(data)
            print(json.dumps(report, indent=4))
        except VaultProcessingError as e:
            print(f"Error: {e.message}", file=sys.stderr)
            sys.exit(e.status_code)
    else:
        print("error: either --input or --serve must be provided")
        sys.exit(1)

if __name__ == "__main__":
    main()
