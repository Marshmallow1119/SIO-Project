import datetime
import sqlite3
import time
from flask import Flask, Response, json, request, jsonify
import base64
import hashlib
import json
import sys
import hashlib
import time
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
from encrypt_comms import decrypt, encrypt


app = Flask(__name__)


DATABASE = 'database.db'
MASTERKEY = b'\xd3\xce\xc9\x91\x12%]\xb9\xbfIc\xf7y\x85b\xb6\xa3o\x1b\xd0\xb2\x01i\x18b\x9e\x00}GM\xebp'
SESSION_LIFETIME = 3600


def verify_nonce(subject_id, organization_id, nonce):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM Nonce JOIN Session ON session_id WHERE Session.subject_id = ? AND Session.organization_id = ? AND Nonce.nonce = ?",
        (subject_id, organization_id, nonce)
    )
    result = cur.fetchone()
    if result is None:
        cur.execute(
            "INSERT INTO Nonce (nonce, session_id) VALUES (?, (SELECT id FROM Session WHERE subject_id = ? AND organization_id = ?))",
            (nonce, subject_id, organization_id)
        )
    conn.commit()
    conn.close()
    return result is None


def verify_sequential_number(subject_id, organization_id, seq_number):
    print("hello????")
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT last_interaction_number FROM Session WHERE subject_id = ? AND organization_id = ?",
        (subject_id, organization_id)
    )
    print("error?")
    result = cur.fetchone()
    print(result["last_interaction_number"])
    print(seq_number)
    if result["last_interaction_number"] > seq_number:
        return False
    cur.execute(
        "UPDATE Session SET last_interaction_number = ? WHERE subject_id = ? AND organization_id = ?",
        (seq_number + 1, subject_id, organization_id)
    )
    conn.commit()
    conn.close()
    return True

def query_db(query, args=(), one=False, commit=False):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    if commit:
        conn.commit()
        conn.close()
        return
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def derive_key(password, salt, iterations=100000):
    try:
        password_bytes = bytes.fromhex(password) 
    except ValueError:
        password_bytes = password.encode('utf-8') 
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt, 
        iterations=iterations, 
        backend=default_backend()
    )
    
    return kdf.derive(password_bytes)

# Routes
@app.route("/organization/list", methods=["GET"])
def org_list():
    orgs = query_db("SELECT * FROM Organization")
    return jsonify([{"id": org["id"], "name": org["name"]} for org in orgs]), 200

@app.route("/organization/create", methods=["POST"])
def create_org():
    data = request.json
    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    publickey = data.get("publickey")

    if not org_name:
        return jsonify({"error": "Organization name is required"}), 400

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        existing_org = query_db("SELECT * FROM Organization WHERE name = ?", (org_name,), one=True)
        if existing_org:
            return jsonify({"error": "Organization already exists"}), 400

        cur.execute("INSERT INTO Organization (name) VALUES (?)", (org_name,))
        org_id = cur.lastrowid

        existing_user = query_db(
            "SELECT * FROM Subject WHERE username = ? OR email = ?",
            (username, email),
            one=True
        )

        if existing_user:
            subject_id = existing_user["id"]
        else:
            cur.execute(
                "INSERT INTO Subject (username, fullname, email) VALUES (?, ?, ?)",
                (username, name, email)
            )
            subject_id = cur.lastrowid

        cur.execute(
            "INSERT INTO Subject_Org (subject_id, organization_id, public_key) VALUES (?, ?, ?)",
            (subject_id, org_id, publickey)
        )

        conn.commit()

        return jsonify({"message": "Organization created successfully"}), 200

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500

    finally:
        conn.close()


@app.route("/organization/subject", methods=["POST"])
def add_subject():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    org = data.get("organization")
    username = data.get("username")
    email = data.get("email")
    fullname = data.get("name")
    public_key = data.get("public_key")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")



    if not verify_nonce(subject_id, org, nonce) or not verify_sequential_number(subject_id, org, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, org),
            one=True
        )
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, org), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, org), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403

        existing_subject = query_db("SELECT * FROM SUBJECT WHERE username = ?", (username,), one=True)
        if not existing_subject:
            cur.execute(
                "INSERT INTO Subject (username, fullname, email) VALUES (?, ?, ?)",
                (username, fullname, email)
            )
            subject_id = cur.lastrowid
        else:
            subject_id = existing_subject["id"]


        exisiting_association = query_db("SELECT * FROM Subject_Org WHERE subject_id = ? AND organization_id = ?", (subject_id, org), one=True)
        if not exisiting_association:
            cur.execute(
                "INSERT INTO Subject_Org (subject_id, organization_id, public_key) VALUES (?, ?, ?)",
                (subject_id, org, public_key)
            )
        else:
            cur.execute(
                "UPDATE Subject_Org SET public_key = ? WHERE subject_id = ? AND organization_id = ?",
                (public_key, subject_id, org)
            )

        cur_time = time.time()
        cur.execute(
            "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
            (cur_time, subject_id, org)
        )
        conn.commit()
        payload = jsonify({"message": "Subject added successfully", "session_data": {"last_interaction": cur_time}})
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object

        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (old_subject_id, org), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")

        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500

    finally:
        conn.close()
        

@app.route("/session/create", methods=["POST"])
def create_session():
    data = request.json
    username = data.get("username")
    organization = data.get("organization")
    last_interaction = time.time()
    public_key = data.get("public_key")
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        conn.execute("BEGIN TRANSACTION")
    
        subject = query_db("SELECT * FROM Subject WHERE username = ?", (username,), one=True)
        if not subject:
            return jsonify({"error": f"Subject with username '{username}' not found"}), 404
        
        subject_id = subject["id"]

        organization_data = query_db("SELECT * FROM Organization WHERE name = ?", (organization,), one=True)
        if not organization_data:
            return jsonify({"error": f"Organization '{organization}' not found"}), 404

        organization_id = organization_data["id"]

        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        
        if session_data:
            last_interaction = session_data["last_interaction"]
            current_time = time.time()

            if current_time - last_interaction > SESSION_LIFETIME:
                session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
                query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
                query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
                expired_seconds = current_time - last_interaction
                expired_seconds = round(expired_seconds, 0)
                return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403

        subject_org = query_db(
            "SELECT * FROM Subject_Org WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if not subject_org:
            return jsonify({"error": f"Subject '{username}' is not associated with organization '{organization}'"}), 403

        existing_session = query_db(
            "SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if existing_session:
            cur.execute(
                "UPDATE Session SET last_interaction = ?, keys = ? WHERE subject_id = ? AND organization_id =  AND last_interaction_number = ?",
                (last_interaction, public_key, subject_id, organization_id, 0)
            )

        cur.execute(
            "INSERT INTO Session (subject_id, organization_id, last_interaction, keys) VALUES (?, ?, ?, ?)",
            (subject_id, organization_id, last_interaction, public_key)
        )
        
        session_data = {
            "organization_id": organization_id,
            "subject_id": subject_id,
            "REP_PUB_KEY": PUBLICKEY
        }
        conn.commit()
        return jsonify({"message": "Session created successfully", "session_data": session_data}), 200
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500
    finally:
        conn.close()

@app.route("/subject/list", methods=["POST"])
def list_subjects():
    try:
        unpadded_data = decrypt(request.json, PRIVATEKEY)
        data = json.loads(unpadded_data)
        username = data.get("username")
        organization_id = data.get("organization_id")
        subject_id = data.get("subject_id")
        nonce = data.get("nonce")
        seq_number = data.get("seq_number")
        if not verify_nonce(subject_id, organization_id, nonce):
            return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police! (Nonce)"}), 403
        
        if not verify_sequential_number(subject_id, organization_id, seq_number):
            return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police! (Seq)"}), 403

        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403        

        if username is not None:
            
            subject = query_db(
                """
                SELECT 
                * FROM Subject WHERE Subject.id = (
                    SELECT subject_id FROM Subject_Org WHERE organization_id = ? AND username = ?
                )
                """,
                (organization_id, username),
                one=True   
            )
            
            if subject:
                query_db("UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?", (current_time, subject["id"], organization_id), commit=True)

                payload = jsonify({"id": subject["id"], "fullname": subject["fullname"], "email": subject["email"], "username": subject["username"], "status": subject["status_"]})
            else:
                return jsonify({"error": "Subject not found"}), 404
        else:
            subjects = query_db(
                """
                SELECT 
                Subject.*, Subject_Org.status_, Subject_Org.public_key FROM Subject JOIN Subject_Org ON Subject.id = Subject_Org.subject_id WHERE organization_id = ?
                """,
                (organization_id,)
            )

            query_db("UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?", (current_time, subject_id, organization_id), commit=True)

            payload = jsonify([{"id": subject["id"], "fullname": subject["fullname"], "email": subject["email"], "username": subject["username"], "status": subject["status_"], "public_key": subject["public_key"]} for subject in subjects])
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/file", methods=["GET"])
def get_file():
    file_handle = request.args.get("file_handle")
    if not file_handle:
        return jsonify({"error": "Missing required parameter: file_handle"}), 400

    try:
        file_handle_bytes = base64.b64decode(file_handle)
    except base64.binascii.Error:
        return jsonify({"error": "Invalid file_handle format. Must be Base64."}), 400

    fileHandle = query_db("SELECT * FROM File WHERE f_handle = ?", (file_handle_bytes,), one=True)
    if not fileHandle:
        return jsonify({"error": "File not found"}), 404

    return jsonify({
        "f_handle": file_handle,
        "content": base64.b64encode(fileHandle["content"]).decode('utf-8')
    }), 200


@app.route("/document/create", methods=["POST"])
def create_document():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    document_name = data.get("document_name")
    file_path = data.get("file_path")
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403


    if not document_name or not file_path:
        return jsonify({"error": "All fields (document_name, file_path) are required"}), 400

    try:
        if not organization_id or not subject_id:
            return jsonify({"error": "Invalid session data"}), 400

        with open(file_path, "rb") as file:
            plaintext = file.read()

        salt = os.urandom(16)            
        nonce = os.urandom(12)           
        password = os.urandom(32).hex()
        derived_key = derive_key(password, salt)

        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)  

        tag = ciphertext[-16:]  
        ciphertext = ciphertext[:-16] 
        f_handle = hashlib.sha256(ciphertext).digest()
    
        alg = f"SHA256|AES-GCM|{salt.hex()}|{nonce.hex()}|{tag.hex()}"
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            conn.execute("BEGIN TRANSACTION")

            session_data = query_db(
                "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
                (subject_id, organization_id),
                one=True
            )
            if not session_data:
                return jsonify({"error": "Invalid session"}), 404

            last_interaction = session_data["last_interaction"]
            current_time = time.time()

            if current_time - last_interaction > SESSION_LIFETIME:
                expired_seconds = current_time - last_interaction
                expired_seconds = round(expired_seconds, 0)
                return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403

            cur.execute(
                "INSERT INTO File (f_handle, content, alg, key) VALUES (?, ?, ?, ?)",
                (f_handle, ciphertext, alg, password)
            )

            today = time.strftime('%Y-%m-%d')
            cur.execute(
                "INSERT INTO Document (name, creation_date, creator, organization_id, f_handle) VALUES (?, ?, ?, ?, ?)",
                (document_name, today, subject_id, organization_id, f_handle)
            )

            last_interaction = time.time()
            cur.execute(
                "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
                (last_interaction, subject_id, organization_id)
            )

            conn.commit()
            payload = jsonify({"message": "Document created successfully", "session_data": {"last_interaction": last_interaction}})
            if isinstance(payload, Response):
                response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
            else:
                response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
            session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
            encrypted_response = encrypt(response_data, session_pub_key)
            return encrypted_response, 200

        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({"error": f"An error occurred: {e}"}), 500

        finally:
            conn.close()

    except FileNotFoundError:
        return jsonify({"error": "File not found at the specified path"}), 400

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid session file format"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
@app.route("/organization/subject/suspend", methods=["POST"])
def suspend_subject():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    username = data.get("username")
    organization = data.get("organization")
    id_subject = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    if not verify_nonce(subject_id, organization, nonce) or not verify_sequential_number(subject_id, organization, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403
    print(organization)
    print(id_subject)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (id_subject, organization),
            one=True
        )
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403
        
        
        subject = query_db(
            """
            SELECT 
            * FROM Subject WHERE Subject.id = (
                SELECT subject_id FROM Subject_Org WHERE organization_id = ? AND username = ?
            )
            """,
            (organization, username),
            one=True   
        )
        subject_id = subject["id"]
        if not subject:
            return jsonify({"error": "Subject not found"}), 404
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500
    finally:
        conn.close()


    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        conn.execute("BEGIN TRANSACTION")
        cur.execute(
            "UPDATE Subject_Org SET status_ = 'suspended' WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization)
        )
        last_interaction = time.time()
        cur.execute(
            "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
            (last_interaction, subject_id, organization)
        )

        conn.commit()
        payload = jsonify({"message": "Subject suspended successfully", "session_data": {"last_interaction": last_interaction}})
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500
    finally:
        conn.close()

@app.route("/organization/subject/activate", methods=["POST"])
def activate_subject():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    username = data.get("username")
    organization = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    if not verify_nonce(subject_id, organization, nonce) or not verify_sequential_number(subject_id, organization, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:    
        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization),
            one=True
        )
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403
        
        subject = query_db(
            """
            SELECT 
            * FROM Subject WHERE Subject.id = (
                SELECT subject_id FROM Subject_Org WHERE organization_id = ? AND username = ?
            )
            """,
            (organization, username),
            one=True   
        )
        subject_id = subject["id"]
        if not subject:
            return jsonify({"error": "Subject not found"}), 404
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500
    finally:
        conn.close()


    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        conn.execute("BEGIN TRANSACTION")
        cur.execute(
            "UPDATE Subject_Org SET status_ = 'active' WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization)
        )
        last_interaction = time.time()
        cur.execute(
            "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
            (last_interaction, subject_id, organization)
        )

        conn.commit()
        payload = jsonify({"message": "Subject activated successfully", "session_data": {"last_interaction": last_interaction}})
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200
    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({"error": f"An error occurred: {e}"}), 500
    finally:
        conn.close()
    


@app.route("/docs/list", methods=["POST"])
def list_docs():
    try:
        data = json.loads(decrypt(request.json, PRIVATEKEY))
        organization_id = data.get("organization_id")
        subject_id = data.get("subject_id")
        username = data.get("username")
        date_filter = data.get("date_filter")
        date_operator = data.get("date_operator")
        nonce = data.get("nonce")
        seq_number = data.get("seq_number")
        if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
            return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403

        if not organization_id or not subject_id:
            return jsonify({"error": "Missing required parameters"}), 400

        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403
        
        query = "SELECT * FROM Document WHERE organization_id = ? AND creator = ?"
        filters = [organization_id, subject_id]

        if username:
            query += " AND EXISTS (SELECT 1 FROM Subject WHERE id = ? AND username = ?)"
            filters.extend([subject_id, username])

        if date_filter and date_operator:
            try:
                date_filter = datetime.strptime(date_filter, "%d-%m-%Y").strftime("%Y-%m-%d")
                if date_operator == "nt":  # mais novo que
                    query += " AND creation_date > ?"
                elif date_operator == "ot":  # mais velho que
                    query += " AND creation_date < ?"
                elif date_operator == "et":  # igual a
                    query += " AND creation_date = ?"
                else:
                    return jsonify({"error": "Invalid date operator"}), 400
                filters.append(date_filter)
            except ValueError:
                return jsonify({"error": "Invalid date format. Use DD-MM-YYYY"}), 400

        docs = query_db(query, filters)
        if docs is None:
            return jsonify({"error": "Database query failed"}), 500

        result = [{
            "d_handle": doc["d_handle"],
            "name": doc["name"],
            "creation_date": doc["creation_date"],
            "creator": doc["creator"],
            "organization_id": doc["organization_id"],
            "f_handle": base64.b64encode(doc["f_handle"]).decode('utf-8') if doc["f_handle"] else None
        } for doc in docs]

        payload = jsonify(result)
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200

    except Exception as e:
        app.logger.error(f"Server error: {str(e)}")
        print(e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/document/metadata", methods=["POST"])
def get_metadata():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    document_name = data.get("document_name")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403
    
    if not organization_id or not subject_id:
        return jsonify({"error": "Invalid session data"}), 400

    try:

        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403
        
        result = query_db(
            "SELECT d.name, d.creation_date, d.creator, d.organization_id, f.content, f.alg, f.key, f.f_handle "
            "FROM Document d "
            "JOIN File f ON d.f_handle = f.f_handle "
            "WHERE d.name = ? AND d.organization_id = ?",
            (document_name, organization_id),
            one=True
        )
        if not result:
            return jsonify({"error": "Document not found or access denied"}), 404

        alg = result["alg"]
        alg_parts = alg.split("|")
        if len(alg_parts) != 5 or alg_parts[0] != "SHA256" or alg_parts[1] != "AES-GCM":
            return jsonify({"error": "Unsupported encryption algorithm"}), 400

        salt = bytes.fromhex(alg_parts[2])
        nonce = bytes.fromhex(alg_parts[3])
        tag = bytes.fromhex(alg_parts[4])
        password = result["key"]

        encrypted_content = result["content"]
        if isinstance(encrypted_content, memoryview):
            encrypted_content = encrypted_content.tobytes() 


        metadata = {
            "document_name": result["name"],
            "creation_date": result["creation_date"],
            "creator": result["creator"],
            "organization_id": result["organization_id"],
            "cipher_text": base64.b64encode(encrypted_content).decode('utf-8'),
            "file_handle": base64.b64encode(result["f_handle"]).decode('utf-8'),
            "password": password,
            "encryption_details": {
                "algorithm": "AES-GCM",
                "salt": salt.hex(),
                "nonce": nonce.hex(),
                "tag": tag.hex()
            }
        }

        payload = jsonify(metadata)
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/document/file", methods=["POST"])
def get_doc_file():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    document_name = data.get("document_name")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403
    
    if not organization_id or not subject_id:
        return jsonify({"error": "Invalid session data"}), 400

    try:
        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403
        
        result = query_db(
            "SELECT d.name, d.creation_date, d.creator, d.organization_id, f.content, f.alg, f.key, f.f_handle "
            "FROM Document d "
            "JOIN File f ON d.f_handle = f.f_handle "
            "WHERE d.name = ? AND d.organization_id = ?",
            (document_name, organization_id),
            one=True
        )
        if not result:
            return jsonify({"error": "Document not found or access denied"}), 404

        alg = result["alg"]
        alg_parts = alg.split("|")
        if len(alg_parts) != 5 or alg_parts[0] != "SHA256" or alg_parts[1] != "AES-GCM":
            return jsonify({"error": "Unsupported encryption algorithm"}), 400

        salt = bytes.fromhex(alg_parts[2])
        nonce = bytes.fromhex(alg_parts[3])
        tag = bytes.fromhex(alg_parts[4])
        password = result["key"]
        derived_key = derive_key(password, salt)
        aesgcm = AESGCM(derived_key)

        encrypted_content = result["content"]
        if isinstance(encrypted_content, memoryview):
            encrypted_content = encrypted_content.tobytes() 
        
        f_handle = query_db("SELECT * From Document WHERE name = ? AND organization_id = ?", (document_name, organization_id), one=True)
        file_handle = f_handle["f_handle"]
        file_handle = base64.b64encode(file_handle).decode('utf-8')
        newDigest = hashlib.sha256(encrypted_content).digest()
        newDigest = base64.b64encode(newDigest).decode('utf-8')

        if newDigest != file_handle:
            return jsonify({"error": "Document file has been tampered with"}), 400

        ciphertext_with_tag = encrypted_content + tag
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None) 

        payload = jsonify({"content": plaintext.decode('utf-8')})
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
        else:
            response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        return encrypted_response, 200

    except sqlite3.Error as e:
        return jsonify({"error": f"Database error: {e}"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/document/delete", methods=["DELETE"])
def delete_document():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    document_name = data.get("document_name")
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        return jsonify({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"}), 403

    if not document_name:
        return jsonify({"error": "All fields (document_name) are required"}), 400

    try:
        if not organization_id or not subject_id:
            return jsonify({"error": "Invalid session data"}), 400
        
        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            return jsonify({"error": "Invalid session"}), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            return jsonify({"error": f"Session expired {expired_seconds} seconds ago"}), 403
        
        doc = query_db(
            "SELECT * FROM Document WHERE organization_id = ? AND creator = ? AND name = ?",
            (organization_id, subject_id, document_name),
            one=True
        )

        if not doc:
            return jsonify({"error": "Document not found"}), 404

        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            conn.execute("BEGIN TRANSACTION")

            cur.execute("DELETE FROM Document WHERE d_handle = ?", (doc["d_handle"],))
            cur.execute("DELETE FROM File WHERE f_handle = ?", (doc["f_handle"],))

            last_interaction = time.time()
            cur.execute(
                "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
                (last_interaction, subject_id, organization_id)
            )

            conn.commit()
            payload = jsonify({"message": "Document deleted successfully", "session_data": {"last_interaction": last_interaction}})
            if isinstance(payload, Response):
                response_data = payload.get_data(as_text=True)  # Extract the JSON string from the Response object
            else:
                response_data = json.dumps(payload)  # For safety, handle cases where payload is not a Response object
            session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
            encrypted_response = encrypt(response_data, session_pub_key)
            return encrypted_response, 200

        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({"error": f"An error occurred: {e}"}), 500

        finally:
            conn.close()

    except FileNotFoundError:
        return jsonify({"error": "Session file not found"}), 400

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid session file format"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

def checkpassword():
    attempted_password = input("Insert password for database: ")
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(attempted_password.encode())
    d = digest.finalize()

    if d == MASTERKEY:
        return
    checkpassword()

if __name__ == "__main__":
    load_dotenv()
    PUBLICKEY=os.getenv('PUBLIC_KEY')
    PRIVATEKEY=os.getenv('PRIVATE_KEY')
    checkpassword()
    app.run(debug=True)