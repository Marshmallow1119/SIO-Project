import base64
from datetime import datetime  
import sqlite3
import time
from flask import Flask, Response, json, request, jsonify
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

import logging



app = Flask(__name__)


DATABASE = 'database.db'
MASTERKEY = b'\xd3\xce\xc9\x91\x12%]\xb9\xbfIc\xf7y\x85b\xb6\xa3o\x1b\xd0\xb2\x01i\x18b\x9e\x00}GM\xebp'
SESSION_LIFETIME = 3600


logger = logging.getLogger('repository_logger')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('repository.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)




def signed_payload(payload):
    rep_private_key = serialization.load_pem_private_key(PRIVATEKEY.encode(), password=None)
    signed_payload = rep_private_key.sign(
        json.dumps(payload, sort_keys=True).encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {"response": payload, "signature": signed_payload.hex()}

def unpack_signed_payload(signed_payload: dict, public_key: str) -> dict:
    rep_pub_key = serialization.load_pem_public_key(public_key.encode())
    response = signed_payload.get("payload")
    signature = bytes.fromhex(signed_payload.get("signature"))
    try:
        rep_pub_key.verify(
            signature,
            json.dumps(response, sort_keys=True).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
    except Exception as e:
        logger.error(f"Error unpacking signed payload: {e}")
        return False
    return True

def verify_signature(subject_id, organization_id, signature):
    #grab the auth_key from the session's subject
    session_data = query_db(
        "SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?",
        (subject_id, organization_id),
        one=True
    )
    if not session_data:
        return False
    keys = session_data["keys"].split("\n--other-key--\n")
    auth_key = bytes.fromhex(keys[1])

    rep_pub_key = serialization.load_pem_public_key(PUBLICKEY.encode())
    try:
        rep_pub_key.verify(
            bytes.fromhex(signature),
            auth_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature as e:
        logger.critical(f"Subject {subject_id} + {organization_id} most likely compromised (invalid signature)")
        return False


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
    else:
        logger.error("Used nonce detected")
        logger.critical(f"Subject {subject_id} + {organization_id} may be compromised (attempted replay attack)")
    conn.commit()
    conn.close()
    return result is None


def verify_sequential_number(subject_id, organization_id, seq_number):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT last_interaction_number FROM Session WHERE subject_id = ? AND organization_id = ?",
        (subject_id, organization_id)
    )
    result = cur.fetchone()
    if result["last_interaction_number"] > seq_number:
        logger.error("Invalid sequence number")
        logger.critical(f"Subject {subject_id} + {organization_id} may be compromised (attempted hijacking attack)")
        return False
    cur.execute(
        "UPDATE Session SET last_interaction_number = ? WHERE subject_id = ? AND organization_id = ?",
        (seq_number + 1, subject_id, organization_id)
    )
    conn.commit()
    conn.close()
    return True

def check_permissions(subject_id, organization_id):
    permissions = {
        "org_permissions": [],
        "doc_permissions": {}
    }
    
    cur_session = query_db(
        "SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?",
        (subject_id, organization_id),
        one=True
    )

    if not cur_session:
        return permissions
    
    assumed_roles = query_db(
        """
        SELECT 
        Role.id FROM Role JOIN Subject_Role ON Role.id = Subject_Role.role_id WHERE Subject_Role.subject_id = ? AND Role.active = '1' AND Subject_Role.assumed = TRUE
        """,
        (subject_id,)
    )

    assumed_roles =  query_db(
        """
        SELECT
        Role.id FROM Role JOIN Subject_Role ON Role.id = Subject_Role.role_id WHERE Subject_Role.subject_id = ?
        """,
        (subject_id,)
    )

    if not assumed_roles:
        return permissions
    
    for role in assumed_roles:
        role_perms_orgs = query_db(
            """
            SELECT 
            Perms.name FROM Perms JOIN Role_Perms ON Perms.id = Role_Perms.perm_id WHERE Role_Perms.role_id = ?
            """,
            (role["id"],)
        )
        
        if role_perms_orgs:
            permissions["org_permissions"].extend([perm["name"] for perm in role_perms_orgs])
        else:
            print(f"No organization permissions found for role_id: {role['id']}")
        
        org_docs = query_db(
            """
            SELECT
            * FROM Document WHERE organization_id = ?
            """,
            (organization_id,)
        )

        if not org_docs:
            print("No organization documents")
            continue

        for document in org_docs:
            doc_perms = query_db(
                """
                SELECT 
                Perms.name FROM Perms JOIN Role_Doc_Perms ON Perms.id = Role_Doc_Perms.perm_id WHERE Role_Doc_Perms.role_id = ? AND Role_Doc_Perms.d_handle = ?
                """,
                (role["id"], document["d_handle"])
            )
            
            if not doc_perms:
                print(f"No document permissions found for role_id: {role['id']} and document: {document['d_handle']}")
                continue
            
            doc_name = document["name"]
            if doc_name not in permissions["doc_permissions"]:
                permissions["doc_permissions"][doc_name] = []
            permissions["doc_permissions"][doc_name].extend([perm["name"] for perm in doc_perms])

    for perm in permissions["org_permissions"]:
        if perm in ["DOC_ACL", "DOC_READ", "DOC_DELETE"]:
            permissions["org_permissions"].remove(perm)

    for doc_name, perms in permissions["doc_permissions"].items():
        permissions["doc_permissions"][doc_name] = list(set(perms))
    return permissions


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
@app.route("/session/authenticate", methods=["POST"])
def send_challenge():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    username = data.get("username")
    organization = data.get("organization")

    subject_org = query_db(
        """
        SELECT 
        * FROM Subject_Org WHERE subject_id = (
            SELECT id FROM Subject WHERE username = ?
        ) AND organization_id = (
            SELECT id FROM Organization WHERE name = ?
        )
        AND Subject_Org.status_ = 'active'
        """,
        (username, organization),
        one=True
    )
    if not subject_org:
        logger.warning(f"Function: send_challenge. Invalid credentials from address {request.remote_addr} (attempted to authenticate with {username} in {organization})")
        return jsonify(signed_payload({"error": "Invalid credentials"})), 401
    challenge_data = query_db(
        "SELECT * FROM Challenge WHERE subject_id = ? AND organization_id = ?",
        (subject_org["subject_id"], subject_org["organization_id"]),
        one=True
    )
    if not challenge_data:
        challenge = os.urandom(32)
        query_db(
            "INSERT INTO Challenge (subject_id, organization_id, challenge, timestamp) VALUES (?, ?, ?, ?)",
            (subject_org["subject_id"], subject_org["organization_id"], challenge, time.time()),
            commit=True
        )
    
    elif time.time() - challenge_data["timestamp"] > 5:
        challenge = os.urandom(32)
        query_db(
            "UPDATE Challenge SET challenge = ?, timestamp = ? WHERE subject_id = ? AND organization_id = ?",
            (challenge, time.time(), subject_org["subject_id"], subject_org["organization_id"]),
            commit=True
        )
    else:
        challenge = challenge_data["challenge"]
    payload = {"challenge": challenge.hex(), "rep_pub_key": PUBLICKEY}
    logger.info(f"Function: send_challenge. Challenge sent to {username} to address {request.remote_addr}")
    return jsonify(signed_payload(payload)), 200

@app.route("/organization/list", methods=["GET"])
def org_list():
    orgs = query_db("SELECT * FROM Organization")
    logger.info(f"Function: org_list. Request from address {request.remote_addr}")
    return jsonify(signed_payload([{"id": org["id"], "name": org["name"]} for org in orgs])), 200

@app.route("/organization/create", methods=["POST"])
def create_org():
    encrypted_data = request.json
    data = json.loads(decrypt(encrypted_data, PRIVATEKEY))
    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    publickey = data.get("public_key")

    if not org_name:
        logger.warning(f"Function: create_org. Wrong payload originating from: {request.remote_addr}")
        return jsonify(signed_payload({"error": "Organization name is required"})), 400

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        existing_org = query_db("SELECT * FROM Organization WHERE name = ?", (org_name,), one=True)
        if existing_org:
            logger.warning(f"Function: create_org. Attempted to create organization {org_name} that already exists, originated from: {request.remote_addr}")
            return jsonify(signed_payload({"error": "Organization already exists"})), 400



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
                "INSERT INTO Subject_Org (subject_id, organization_id, public_key) VALUES (?, ?, ?)",(subject_id, org_id, publickey))
            cur.execute(
                "INSERT INTO Role (name, organization_id) VALUES ('Manager', ?)",
                (org_id,)
            )

            role_id = cur.lastrowid

            cur.execute("INSERT INTO Subject_Role (subject_id, role_id) VALUES (?, ?)",(subject_id, role_id))

            numRowsPerms = cur.execute("SELECT * FROM Perms").fetchall()
            numRowsPerms = len(numRowsPerms)
            if numRowsPerms == 0:
                cur.execute("INSERT INTO Perms (name) VALUES ('ROLE_ACL')")
                cur.execute("INSERT INTO Perms (name) VALUES ('SUBJECT_NEW')")
                cur.execute("INSERT INTO Perms (name) VALUES ('SUBJECT_DOWN')")
                cur.execute("INSERT INTO Perms (name) VALUES ('SUBJECT_UP')")
                cur.execute("INSERT INTO Perms (name) VALUES ('DOC_NEW')")
                cur.execute("INSERT INTO Perms (name) VALUES ('ROLE_NEW')")
                cur.execute("INSERT INTO Perms (name) VALUES ('ROLE_DOWN')")
                cur.execute("INSERT INTO Perms (name) VALUES ('ROLE_UP')")
                cur.execute("INSERT INTO Perms (name) VALUES ('ROLE_MOD')")
                cur.execute("INSERT INTO Perms (name) VALUES ('DOC_ACL')")
                cur.execute("INSERT INTO Perms (name) VALUES ('DOC_DELETE')") 
                cur.execute("INSERT INTO Perms (name) VALUES ('DOC_READ')")  

            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (1, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (2, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (3, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (4, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (5, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (6, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (7, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (8, role_id))
            cur.execute("INSERT INTO Role_Perms (perm_id, role_id) VALUES (?, ?)", (9, role_id))

        conn.commit()
        logger.info(f"Function: create_org. Organization {org_name} created by subject {username} from address {request.remote_addr}")
        return jsonify(signed_payload({"message": "Organization created successfully"})), 200
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Function: create_org. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/organization/subject", methods=["POST"])
def add_subject():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    org = data.get("organization")
    username = data.get("username")
    email = data.get("email")
    fullname = data.get("name")
    public_key = data.get("public_key")
    subject_id = data.get("subject")
    old_subject_id = data.get("subject")

    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")

    if not verify_signature(subject_id, org, signature):
        logger.info(f"Function: add_subject. Subject {subject_id} failed to authenticate")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, org, nonce) or not verify_sequential_number(subject_id, org, seq_number):
        logger.info(f"Function: add_subject. Subject {subject_id} failed to authenticate")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
    
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, org),
            one=True
        )
        
        if not session_data:
            logger.debug(f"Function: add_subject. Somehow the session data is missing for subject {subject_id} and organization {org} despite passing in previous checks")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: add_subject. Session regarding subject {subject_id} and organization {org} is compromised.")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        
        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, org), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, org), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: add_subject. Session expired {expired_seconds} seconds ago for subject {subject_id} and organization {org}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, org)
        if not permissions:
            logger.info(f"Function: add_subject. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        if "SUBJECT_NEW" not in permissions["org_permissions"]:
            logger.info(f"Function: add_subject. Subject {subject_id} does not have permission to add new subject. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to add new subject"})), 403

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
            response_data = payload.get_data(as_text=True) 
        else:
            response_data = json.dumps(payload) 
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (old_subject_id, org), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")

        encrypted_response = encrypt(response_data, session_pub_key)
        logger.info(f"Function: add_subject. Subject {subject_id} added successfully to organization {org}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200

    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Function: add_subject. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/session/create", methods=["POST"])
def create_session():
    data = json.loads(decrypt(request.json, PRIVATEKEY))
    username = data.get("username")
    organization = data.get("organization")
    last_interaction = time.time()
    public_key = data.get("public_key")
    challenge_signature = data.get("challenge")

    if not challenge_signature:
        logger.warning(f"Function: create_session. No challenge response from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "No challenge response"})), 400
    try:
        #get subject in org
        subject_org = query_db(
            "SELECT * FROM Subject_Org WHERE subject_id = (SELECT id FROM Subject WHERE username = ?) AND organization_id = (SELECT id FROM Organization WHERE name = ?)",
            (username, organization),
            one=True
        )
        if not subject_org:
            logger.warning(f"Function: create_session. Client in address {request.remote_addr} attempted to create a session for non-existent subject {username} in {organization}")
            return jsonify(signed_payload({"error": "Invalid credentials"})), 403
        organization_id = subject_org["organization_id"]

        
        #get challenge from db
        challenge_data = query_db(
            "SELECT * FROM Challenge WHERE subject_id = ? AND organization_id = ?",
            (subject_org["subject_id"], organization_id),
            one=True
        )

        if not challenge_data:
            logger.warning(f"Function: create_session. Challenge not found for subject {username} in {organization}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid credentials"})), 403
        
        if challenge_data["timestamp"] - time.time() > 5:
            logger.warning(f"Function: create_session. Challenge expired for subject {username} in {organization}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Challenge expired"})), 403
        challenge = challenge_data["challenge"].hex()
        #get subject's public key
        subject_pub_key = query_db("SELECT public_key FROM Subject_Org WHERE subject_id = ? AND organization_id = ?", (subject_org["subject_id"], organization_id), one=True)
        if not subject_pub_key:
            logger.warning(f"Function: create_session. Public key not found for subject {username} in {organization}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid credentials"})), 403
        loaded_pub_key = serialization.load_pem_public_key(subject_pub_key["public_key"].encode())
        #verify challenge
        loaded_pub_key.verify(
            bytes.fromhex(challenge_signature),
            bytes.fromhex(challenge),
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as e:
        logger.warning(f"Function: create_session. Invalid signature for subject {username} in {organization}. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid credentials"})), 403
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        conn.execute("BEGIN TRANSACTION")
    
        subject = query_db("SELECT * FROM Subject WHERE username = ?", (username,), one=True)
        if not subject:
            logger.warning(f"Function: create_session. Subject with username {username} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Subject with username '{username}' not found"})), 404
        
        subject_id = subject["id"]

        organization_data = query_db("SELECT * FROM Organization WHERE name = ?", (organization,), one=True)
        if not organization_data:
            logger.warning(f"Function: create_session. Organization {organization} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Organization '{organization}' not found"})), 404

        organization_id = organization_data["id"]

        session_data = query_db(
            "SELECT last_interaction FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        
        #generate auth key
        auth_key = os.urandom(32)

        #sign auth key
        rep_private_key = serialization.load_pem_private_key(PRIVATEKEY.encode(), password=None)
        signature = rep_private_key.sign(
            auth_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        subject_org = query_db(
            "SELECT * FROM Subject_Org WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if subject_org["status_"] != "active":
            logger.warning(f"Function: create_session. Subject {username} is suspended. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Subject '{username}' is suspended"})), 403
        if not subject_org:
            logger.warning(f"Function: create_session. Subject {username} is not associated with organization {organization}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Subject '{username}' is not associated with organization '{organization}'"})), 403
        
        keys_text = public_key + "\n--other-key--\n" + auth_key.hex()

        subject_org = query_db(
            "SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if subject_org:
            cur.execute(
                "UPDATE Session SET last_interaction = ?, keys = ?, last_interaction_number = ? WHERE subject_id = ? AND organization_id = ?",
                (last_interaction, keys_text, 0, subject_id, organization_id)
            )
        else:
            cur.execute(
                "INSERT INTO Session (subject_id, organization_id, last_interaction, keys) VALUES (?, ?, ?, ?)",
                (subject_id, organization_id, last_interaction, keys_text)
            )    
        
        session_data = {
            "organization_id": organization_id,
            "subject_id": subject_id,
            "REP_PUB_KEY": PUBLICKEY,
            "signature": signature.hex(),
        }
        conn.commit()
        logger.info(f"Function: create_session. Session created for subject {username} in {organization}. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"message": "Session created successfully", "session_data": session_data})), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: create_session. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/subject/list", methods=["POST"])
def list_subjects():
    try:
        data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
        username = data.get("username")
        organization_id = data.get("organization_id")
        subject_id = data.get("subject_id")
        nonce = data.get("nonce")
        seq_number = data.get("seq_number")

        signature = data.get("signature")
        if not verify_signature(subject_id, organization_id, signature):
            logger.warning(f"Function: list_subjects. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Authentication failed"})), 403

        if not verify_nonce(subject_id, organization_id, nonce):
            logger.warning(f"Function: list_subjects. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police! (Nonce)"})), 403
        
        if not verify_sequential_number(subject_id, organization_id, seq_number):
            logger.warning(f"Function: list_subjects. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police! (Seq)"})), 403

        session_data = query_db(
            "SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        session_pub_key = session_data["keys"].split("\n--other-key--\n")[0]
        if not session_pub_key:
            logger.warning(f"Function: list_subjects. Subject {subject_id} doesn't exist. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject not found"})), 404
        if not unpack_signed_payload(request.json, session_pub_key):
            logger.critical(f"Function: list_subjects. Subject {subject_id} is likely compromised (invalid session signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403
        
        if not session_data:
            logger.warning(f"Function: list_subjects. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_subjects. Session expired {expired_seconds} seconds ago for subject {subject_id} in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403        

        if username is not None:
            
            subject = query_db(
                """
                SELECT 
                    *
                FROM 
                    Subject 
                JOIN 
                    Subject_Org ON Subject.id = Subject_Org.subject_id 
                WHERE 
                    Subject_Org.organization_id = ? AND Subject.username = ?
                """,
                (organization_id, username),
                one=True   
            )
            if subject:
                query_db("UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?", (current_time, subject["id"], organization_id), commit=True)

                payload = jsonify({"id": subject["id"], "fullname": subject["fullname"], "email": subject["email"], "username": subject["username"], "status": subject["status_"]})
            else:
                logger.warning(f"Function: list_subjects. Subject {username} not found in organization {organization_id}. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Subject not found"})), 404
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
            response_data = payload.get_data(as_text=True) 
        else:
            response_data = json.dumps(payload) 
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        logger.info(f"Function: list_subjects. Subjects listed for organization {organization_id}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except Exception as e:
        logger.error(f"Function: list_subjects. With payload {data}: {e}")
        return jsonify(signed_payload({"error": str(e)})), 500




@app.route("/file", methods=["GET"])
def get_file():
    file_handle = request.args.get("file_handle")
    if not file_handle:
        logger.warning(f"Function: get_file. Missing required parameter: file_handle. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Missing required parameter: file_handle"})), 400

    fileHandle = query_db("SELECT * FROM File WHERE f_handle = ?", (file_handle,), one=True)
    if not fileHandle:
        logger.warning(f"Function: get_file. File {file_handle} not found. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "File not found"})), 404

    content = base64.b64encode(fileHandle["content"]).decode("utf-8")

    return jsonify(signed_payload({
        "f_handle": file_handle, 
        "content": content 
    })), 200



@app.route("/document/create", methods=["POST"])
def create_document():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    document_name = data.get("document_name")
    file_path = data.get("file_path")
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    print(data)
    signature = data.get("signature")
    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: create_document. Subject {subject_id} in organization {organization_id} failed to authenticate, likely compromised (invalid signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: create_document. Subject {subject_id} in organization {organization_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403


    if not document_name or not file_path:
        logger.warning(f"Function: create_document. Missing required fields (document_name, file_path). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "All fields (document_name, file_path) are required"})), 400

    try:
        if not organization_id or not subject_id:
            logger.warning(f"Function: create_document. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
            return jsonify(signed_payload(({"error": "Invalid session data"}))), 400

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
        f_handle = hashlib.sha256(plaintext).hexdigest()
    
        alg = f"SHA256|AES-GCM|{salt.hex()}|{nonce.hex()}|{tag.hex()}"
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            conn.execute("BEGIN TRANSACTION")

            session_data = query_db(
                "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
                (subject_id, organization_id),
                one=True
            )
            if not session_data:
                logger.warning(f"Function: create_document. Invalid session for subject {subject_id} in organization {organization_id}. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Invalid session"})), 404
            
            keys = session_data["keys"].split("\n--other-key--\n")
            if not unpack_signed_payload(request.json, keys[0]):
                logger.critical(f"Function: create_document. Subject {subject_id} in organization {organization_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Invalid authentication"})), 403

            last_interaction = session_data["last_interaction"]
            current_time = time.time()

            if current_time - last_interaction > SESSION_LIFETIME:
                expired_seconds = current_time - last_interaction
                expired_seconds = round(expired_seconds, 0)
                logger.warning(f"Function: create_document. Session expired {expired_seconds} seconds ago for subject {subject_id} in organization {organization_id}. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
            
            permissions = check_permissions(subject_id, organization_id)
            if not permissions:
                logger.warning(f"Function: create_document. Subject {subject_id} in organization {organization_id} does not have any permissions. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

            subject_roles = query_db("SELECT * FROM Role JOIN Subject_Role ON Role.id = Subject_Role.role_id WHERE Subject_Role.subject_id = ? AND Role.active = '1' AND Subject_Role.assumed = TRUE AND Role.organization_id = ?", (subject_id, organization_id))

            if "DOC_NEW" not in permissions["org_permissions"]:
                logger.warning(f"Function: create_document. Subject {subject_id} in organization {organization_id} does not have permission to add new document. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Subject does not have permission to add new document"})), 403

            cur.execute("INSERT INTO File (f_handle, content, alg, key) VALUES (?, ?, ?, ?)", (f_handle, ciphertext, alg, password))

            today = time.strftime('%Y-%m-%d')
            cur.execute(
                "INSERT INTO Document (name, creation_date, creator, organization_id, f_handle) VALUES (?, ?, ?, ?, ?)",
                (document_name, today, subject_id, organization_id, f_handle)
            )
            id_doc = cur.lastrowid
            findAllRoleDocPerms = cur.execute("SELECT * FROM Role_Doc_Perms").fetchall()

            for row in findAllRoleDocPerms:
                print(dict(row)) 
    
            for subject in subject_roles:
                cur.execute("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, 10)", (subject["role_id"], id_doc))
                cur.execute("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, 11)",(subject["role_id"], id_doc))
                cur.execute("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, 12)",(subject["role_id"], id_doc))

            if "Manager" not in [role["name"] for role in subject_roles]:
                manager = query_db("SELECT Role.id FROM Role WHERE name = 'Manager' AND organization_id = ?", (organization_id,), one=True)

                cur.execute("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, 10)",(manager["id"], id_doc))
                cur.execute("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, 11)", (manager["id"], id_doc))
                cur.execute("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, 12)",(manager["id"], id_doc))
                
                
            last_interaction = time.time()
            cur.execute(
                "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
                (last_interaction, subject_id, organization_id)
            )
            
            conn.commit()
            payload = jsonify({"message": "Document created successfully", "session_data": {"last_interaction": last_interaction}})
            if isinstance(payload, Response):
                response_data = payload.get_data(as_text=True)  
            else:
                response_data = json.dumps(payload)  
            session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
            encrypted_response = encrypt(response_data, session_pub_key)
            logger.info(f"Function: create_document. Document {document_name} created successfully by subject {subject_id} in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload(encrypted_response)), 200

        except sqlite3.Error as e:
            conn.rollback()
            conn.close()
            logger.error(f"Function: create_document. With payload {data}: {e}")
            return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500
    except FileNotFoundError:
        logger.error(f"Function: create_document. File not found at the specified path. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "File not found at the specified path"})), 400

    except json.JSONDecodeError:
        logger.warning(f"Function: create_document. Invalid session file format. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session file format"})), 400

    except Exception as e:
        logger.error(f"Function: create_document. With payload {data}: {e}")
        return jsonify(signed_payload({"error": str(e)})), 500

    
@app.route("/organization/subject/suspend", methods=["POST"])
def suspend_subject():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    username = data.get("username")  # User to suspend
    organization = data.get("organization")
    subject_id = data.get("subject")  # User making the request
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    
    signature = data.get("signature")
    if not verify_signature(subject_id, organization, signature):
        logger.critical(f"Function: suspend_subject. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization, nonce) or not verify_sequential_number(subject_id, organization, seq_number):
        logger.warning(f"Function: suspend_subject. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization),
            one=True
        )
        if not session_data:
            logger.warning(f"Function: suspend_subject. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.warning(f"Function: suspend_subject. Subject {subject_id} is likely compromised (invalid session signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: suspend_subject. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, organization)
        if not permissions:
            logger.warning(f"Function: suspend_subject. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        if "SUBJECT_DOWN" not in permissions["org_permissions"]:
            logger.warning(f"Function: suspend_subject. Subject {subject_id} does not have permission to suspend subject. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to suspend subject"})), 403

        # Find the subject we are trying to suspend
        findSubject = query_db("SELECT * FROM Subject WHERE username = ?", (username,), one=True)
        if not findSubject:
            return jsonify(signed_payload({"error": "Subject not found"})), 404

        findIfManager = query_db(
            """
            SELECT Role.name FROM Role
            JOIN Subject_Role ON Role.id = Subject_Role.role_id
            WHERE Subject_Role.subject_id = ? AND Subject_Role.assumed = TRUE
            """,
            (findSubject["id"],),
            one=True
        )

        findSubject = query_db("SELECT * FROM Subject WHERE username = ?", (username,), one=True)
        if not findSubject:
            logger.warning(f"Function: suspend_subject. Subject {username} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject not found"})), 404
        if findIfManager and findIfManager["name"] == "Manager":
            logger.warning(f"Function: suspend_subject. Manager {subject_id} cannot be suspended. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Cannot suspend a Manager"})), 403
          
        # Check if the user is already suspended
        alreadySuspended = query_db(
            "SELECT * FROM Subject_Org WHERE subject_id = ? AND organization_id = ? AND status_ = 'suspended'",
            (findSubject["id"], organization),
            one=True
        )
        if alreadySuspended:
            logger.warning(f"Function: suspend_subject. Subject {username} is already suspended. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject is already suspended"})), 403

        # Suspend the subject
        query_db(
            """
            UPDATE Subject_Org
            SET status_ = 'suspended'
            WHERE organization_id = ? AND subject_id = ?
            """,
            (organization, findSubject["id"]),
            commit=True
        )

        # Verify suspension
        verifySuspended = query_db(
            "SELECT * FROM Subject_Org WHERE subject_id = ? AND organization_id = ? AND status_ = 'suspended'",
            (findSubject["id"], organization),
            one=True
        )
        if not verifySuspended:
            logger.warning(f"Function: suspend_subject. Failed to suspend subject {username}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Failed to suspend subject"})), 500

        encrypted_response = encrypt("Subject %s suspended successfully" % username, keys[0])
        logger.warning(f"Function: suspend_subject. Subject {username} suspended successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200

    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: suspend_subject. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

    finally:
        conn.close()


@app.route("/organization/subject/activate", methods=["POST"])
def activate_subject():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    username = data.get("username")
    organization = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")

    signature = data.get("signature")
    if not verify_signature(subject_id, organization, signature):
        logger.critical(f"Function: activate_subject. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization, nonce) or not verify_sequential_number(subject_id, organization, seq_number):
        logger.warning(f"Function: activate_subject. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:    
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization),
            one=True
        )
        if not session_data:
            logger.warning(f"Function: activate_subject. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: activate_subject. Subject {subject_id} is likely compromised (invalid session signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: activate_subject. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, organization)
        if not permissions:
            logger.warning(f"Function: activate_subject. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        subject_roles = query_db("""
            SELECT Role.id FROM Role 
            JOIN Subject_Role ON Role.id = Subject_Role.role_id 
            JOIN Subject_Org ON Subject_Role.subject_id = Subject_Org.subject_id 
            WHERE Subject_Org.subject_id = ? 
            AND Subject_Org.status_ = 'active' 
            AND Subject_Role.assumed = TRUE
        """, (subject_id,))

        permissions = []

        if not subject_roles:
            logger.warning(f"Function: activate_subject. Subject {subject_id} does not have any roles. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any roles"})), 403
        
        for role in subject_roles:
            role_perms = query_db("""SELECT Perms.name FROM Perms JOIN Role_Perms ON Perms.id = Role_Perms.perm_id WHERE Role_Perms.role_id = ?""",(role))
            permissions.extend([perm["name"] for perm in role_perms])

        if "SUBJECT_UP" not in permissions: 
            logger.warning(f"Function: activate_subject. Subject {subject_id} does not have permission to activate subject. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to activate subject"})), 403

        subject_to_activate = query_db(
            "SELECT * FROM Subject_Org JOIN Subject ON Subject_Org.subject_id = Subject.id WHERE username = ? AND organization_id = ?",
            (username, organization),
            one=True
        )
        if not subject_to_activate:
            logger.warning(f"Function: activate_subject. Subject {username} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject not found"})), 404
        else:
            subject_id_activate = subject_to_activate["subject_id"]
            query_db(
                "UPDATE Subject_Org SET status_ = 'active' WHERE subject_id = ? AND organization_id = ?",
                (subject_id_activate, organization),
                commit=True
            )
    
            
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: activate_subject. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

    
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
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Subject %s activated successfully!" % username, session_pub_key)
        logger.info(f"Function: activate_subject. Subject {username} activated successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: activate_subject. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/docs/list", methods=["POST"])
def list_docs():
    try:
        data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
        organization_id = data.get("organization_id")
        subject_id = data.get("subject_id")
        username = data.get("username")
        date_filter = data.get("date_filter")
        date_operator = data.get("date_operator")
        nonce = data.get("nonce")
        seq_number = data.get("seq_number")
        signature = data.get("signature")

        if not verify_signature(subject_id, organization_id, signature):
            logger.critical(f"Function: list_docs. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Authentication failed"})), 403

        if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
            logger.warning(f"Function: list_docs. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

        if not organization_id or not subject_id:
            logger.warning(f"Function: list_docs. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Missing required parameters"})), 400

        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if not session_data:
            logger.warning(f"Function: list_docs. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        session_pub_key = session_data["keys"].split("\n--other-key--\n")[0]
        if not unpack_signed_payload(request.json, session_pub_key):
            logger.critical(f"Function: list_docs. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403
        

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_docs. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
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
                    logger.error(f"Function: list_docs. Invalid date operator {date_operator}. Request from address {request.remote_addr}")
                    return jsonify(signed_payload({"error": "Invalid date operator"})), 400
                filters.append(date_filter)
            except ValueError:
                logger.error(f"Function: list_docs. Invalid date format. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Invalid date format. Use DD-MM-YYYY"})), 400

        docs = query_db(query, filters)
        if docs is None:
            return jsonify(signed_payload({"error": "Database query failed"})), 500
        if not docs:
            logger.warning(f"Function: list_docs. No documents found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "No documents found"})), 404
        result = [{
            "d_handle": doc["d_handle"],
            "name": doc["name"],
            "creation_date": doc["creation_date"],
            "creator": doc["creator"],
            "organization_id": doc["organization_id"],
            "f_handle": doc["f_handle"]
        } for doc in docs]

        payload = jsonify(result)
        
        if isinstance(payload, Response):
            response_data = payload.get_data(as_text=True)   
        else:
            response_data = json.dumps(payload) 
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        signed_response = signed_payload(encrypted_response)
        logger.info(f"Function: list_docs. Documents listed successfully for subject {subject_id}. Request from address {request.remote_addr}")
        return jsonify(signed_response), 200

    except Exception as e:
        app.logger.error(f"Server error: {str(e)}")
        logger.error(f"Function: list_docs. With payload {data}: {e}")
        return jsonify(signed_payload({"error": "Internal server error"})), 500

@app.route("/document/metadata", methods=["POST"])
def get_metadata():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    document_name = data.get("document_name")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    
    signature = data.get("signature")
    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: get_metadata. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: get_metadata. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403
    
    if not organization_id or not subject_id:
        logger.warning(f"Function: get_metadata. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
                (subject_id, organization_id)
            )
            session_data = cursor.fetchone()
            if not session_data:
                logger.warning(f"Function: get_metadata. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Invalid session"})), 404
            
            keys = session_data["keys"].split("\n--other-key--\n")
            if not unpack_signed_payload(request.json, keys[0]):
                logger.critical(f"Function: get_metadata. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Invalid authentication"})), 403
            
            last_interaction = session_data["last_interaction"]
            current_time = time.time()
            
            if current_time - last_interaction > SESSION_LIFETIME:
                cursor.execute("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id))
                session = cursor.fetchone()
                cursor.execute("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id))
                cursor.execute("DELETE FROM Nonce WHERE session_id = ?", (session["id"],))
                conn.commit()
                expired_seconds = round(current_time - last_interaction, 0)
                logger.warning(f"Function: get_metadata. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
            
            permissions = check_permissions(subject_id, organization_id)
            if not permissions:
                logger.warning(f"Function: get_metadata. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403
            
            document_permissions = permissions.get("doc_permissions", {})
            doc_permissions = document_permissions.get(document_name)
            
            if not doc_permissions or "DOC_READ" not in doc_permissions:
                logger.warning(f"Function: get_metadata. Subject {subject_id} does not have permission to read this document. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Subject does not have permission to read this document"})), 403
            
            cursor.execute(
                "SELECT d.name, d.creation_date, d.creator, d.organization_id, f.content, f.alg, f.key, f.f_handle "
                "FROM Document d "
                "JOIN File f ON d.f_handle = f.f_handle "
                "WHERE d.name = ? AND d.organization_id = ?",
                (document_name, organization_id)
            )
            result = cursor.fetchone()
            if not result:
                logger.warning(f"Function: get_metadata. Document {document_name} not found or access denied. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Document not found or access denied"})), 404
            
            alg = result["alg"].split("|")
            if len(alg) != 5 or alg[0] != "SHA256" or alg[1] != "AES-GCM":
                logger.error(f"Function: get_metadata. Unsupported encryption algorithm (attempted {alg}). Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Unsupported encryption algorithm"})), 400
            
            salt = bytes.fromhex(alg[2])
            nonce = bytes.fromhex(alg[3])
            tag = bytes.fromhex(alg[4])
            password = result["key"]
            encrypted_content = result["content"]
            
            if isinstance(encrypted_content, memoryview):
                encrypted_content = encrypted_content.tobytes()
            
            metadata = {
                "document_name": result["name"],
                "creation_date": result["creation_date"],
                "creator": result["creator"],
                "organization_id": result["organization_id"],
                "cipher_text": base64.b64encode(encrypted_content).decode("utf-8"),
                "file_handle": result["f_handle"],
                "password": password,
                "encryption_details": {
                    "algorithm": "AES-GCM",
                    "salt": salt.hex(),
                    "nonce": nonce.hex(),
                    "tag": tag.hex()
                }
            }
            
            cursor.execute("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id))
            session_pub_key = cursor.fetchone()["keys"].replace("\\n", "\n")
            encrypted_response = encrypt(json.dumps(metadata), session_pub_key)
            logger.info(f"Function: get_metadata. Metadata for document {document_name} retrieved successfully by subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload(encrypted_response)), 200
    
    except sqlite3.Error as e:
        logger.error(f"Function: get_metadata. Database error: {e}")
        return jsonify(signed_payload({"error": f"Database error: {e}"})), 500
    
    except Exception as e:
        logger.error(f"Function: get_metadata. With payload {data}: {e}")
        return jsonify(signed_payload({"error": str(e)})), 500


@app.route("/document/file", methods=["POST"])
def get_doc_file():
    try:
        data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
        organization_id = data.get("organization_id")
        subject_id = data.get("subject_id")
        document_name = data.get("document_name")
        nonce = data.get("nonce")
        seq_number = data.get("seq_number")
        signature = data.get("signature")

        if not verify_signature(subject_id, organization_id, signature):
            logger.critical(f"Function: get_doc_file. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Authentication failed"})), 403

        if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
            logger.warning(f"Function: get_doc_file. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid nonce or sequence number"})), 403
        
        if not organization_id or not subject_id:
            logger.warning(f"Function: get_doc_file. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session data"})), 400

        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )
        if not session_data:
            logger.warning(f"Function: get_doc_file. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404

        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: get_doc_file. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()
        if current_time - last_interaction > SESSION_LIFETIME:
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            expired_seconds = round(current_time - last_interaction, 0)
            logger.warning(f"Function: get_doc_file. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        permissions = check_permissions(subject_id, organization_id)
        if not permissions:
            logger.warning(f"Function: get_doc_file. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403
        
        document_permissions = permissions.get("doc_permissions", {})
        doc_permissions = document_permissions.get(document_name)
        print(doc_permissions)
        if not doc_permissions or "DOC_READ" not in doc_permissions:
            logger.warning(f"Function: get_doc_file. Subject {subject_id} does not have permission to read this document. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to read this document"})), 403
        
        result = query_db(
            "SELECT d.name, d.creation_date, d.creator, d.organization_id, f.content, f.alg, f.key, f.f_handle "
            "FROM Document d "
            "JOIN File f ON d.f_handle = f.f_handle "
            "WHERE d.name = ? AND d.organization_id = ?",
            (document_name, organization_id),
            one=True
        )
        if not result:
            logger.warning(f"Function: get_doc_file. Document {document_name} not found or access denied. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Document not found or access denied"})), 404

        alg = result["alg"]
        alg_parts = alg.split("|")
        if len(alg_parts) != 5 or alg_parts[0] != "SHA256" or alg_parts[1] != "AES-GCM":
            logger.error(f"Function: get_doc_file. Unsupported encryption algorithm (attempted {alg}). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Unsupported encryption algorithm"})), 400

        salt = bytes.fromhex(alg_parts[2])
        nonce = bytes.fromhex(alg_parts[3])
        tag = bytes.fromhex(alg_parts[4])
        password = result["key"]
        derived_key = derive_key(password, salt)
        aesgcm = AESGCM(derived_key)

        encrypted_content = result["content"]
        if isinstance(encrypted_content, memoryview):
            encrypted_content = encrypted_content.tobytes()

        ciphertext_with_tag = encrypted_content + tag
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        file_handle_record = query_db("SELECT f_handle FROM Document WHERE name = ? AND organization_id = ?", (document_name, organization_id), one=True)
        stored_file_handle = file_handle_record["f_handle"]

        computed_hash = hashlib.sha256(plaintext).hexdigest()
        if computed_hash != stored_file_handle:
            logger.critical(f"Function: get_doc_file. Document file {document_name} has been tampered with. DB may be compromised. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Document file has been tampered with"})), 400

        response_data = json.dumps({"content": plaintext.decode('utf-8')})
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(response_data, session_pub_key)
        logger.info(f"Function: get_doc_file. Document file {document_name} retrieved successfully by subject {subject_id}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200

    except sqlite3.Error as e:
        logger.error(f"Function: get_doc_file. Database error: {e}")
        return jsonify(signed_payload({"error": f"Database error: {e}"})), 500

    except Exception as e:
        logger.error(f"Function: get_doc_file. With payload {data}: {e}")
        return jsonify(signed_payload({"error": str(e)})), 500




@app.route("/document/delete", methods=["DELETE"])
def delete_document():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    document_name = data.get("document_name")
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")

    signature = data.get("signature")
    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: delete_document. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: delete_document. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not document_name:
        logger.warning(f"Function: delete_document. Missing required fields (document_name). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "All fields (document_name) are required"})), 400

    try:
        if not organization_id or not subject_id:
            logger.warning(f"Function: delete_document. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session data"})), 400
        
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: delete_document. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: delete_document. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: delete_document. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        doc = query_db(
            "SELECT * FROM Document WHERE organization_id = ? AND creator = ? AND name = ?",
            (organization_id, subject_id, document_name),
            one=True
        )

        if not doc:
            logger.warning(f"Function: delete_document. Document {document_name} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Document not found"})), 404

        permissions = check_permissions(subject_id, organization_id)
        
        document_permissions = permissions.get("doc_permissions", {})
        doc_permissions = document_permissions.get(document_name)
        
        if not doc_permissions:
            logger.warning(f"Function: delete_document. Subject {subject_id} does not have permission to access this document. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to access this document"})), 403
        
        if "DOC_READ" not in doc_permissions:
            logger.warning(f"Function: delete_document. Subject {subject_id} does not have permission to read this document. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to read this document"})), 403

        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            conn.execute("BEGIN TRANSACTION")
            cur.execute("DELETE FROM Document WHERE d_handle = ?", (doc["d_handle"],))
            cur.execute("DELETE FROM Role_Doc_Perms WHERE d_handle = ?", (doc["d_handle"],))

            last_interaction = time.time()
            cur.execute(
                "UPDATE Session SET last_interaction = ? WHERE subject_id = ? AND organization_id = ?",
                (last_interaction, subject_id, organization_id)
            )

            conn.commit()
            payload = jsonify({"message": "Document deleted successfully", "session_data": {"last_interaction": last_interaction}})
            if isinstance(payload, Response):
                response_data = payload.get_data(as_text=True)
            else:
                response_data = json.dumps(payload) 
            session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
            encrypted_response = encrypt(response_data, session_pub_key)
            logger.info(f"Function: delete_document. Document {document_name} deleted successfully by subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload(encrypted_response)), 200

        except sqlite3.Error as e:
            conn.rollback()
            conn.close()
            logger.error(f"Function: delete_document. With payload {data}: {e}")
            return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

    except FileNotFoundError:
        logger.error(f"Function: delete_document. Session file not found. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Session file not found"})), 400

    except json.JSONDecodeError:
        logger.error(f"Function: delete_document. Invalid session file format. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session file format"})), 400

    except Exception as e:
        logger.error(f"Function: delete_document. With payload {data}: {e}")
        return jsonify(signed_payload({"error": str(e)})), 500
    

@app.route("/role/add", methods=["POST"])
def add_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")

    signature = data.get("signature")
    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: add_role. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: add_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: add_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: add_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: add_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: add_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, organization_id)
        if not permissions:
            logger.warning(f"Function: add_role. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403
        
        if "ROLE_NEW" not in permissions["org_permissions"]:
            logger.warning(f"Function: add_role. Subject {subject_id} does not have permission to add a role to the organization. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to add role to organization"})), 403
        
        findOrganization = query_db("SELECT * FROM Organization WHERE id = ?", (organization_id,), one=True)
        if not findOrganization:
            logger.warning(f"Function: add_role. Organization {organization_id} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Organization not found"})), 404

        findRole = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if findRole:
            logger.warning(f"Function: add_role. Role {role_name} already exists in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role already exists in the organization"})), 409

        query_db("INSERT INTO Role (name, organization_id) VALUES (?, ?)", (role_name, organization_id), commit=True)

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Role added successfully to organization", session_pub_key)
        logger.info(f"Function: add_role. Role {role_name} added successfully to organization {organization_id} by subject {subject_id}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: add_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

@app.route("/role/suspend", methods=["POST"])
def suspend_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")

    signature = data.get("signature")
    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: suspend_role. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: suspend_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: suspend_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if role_name.lower() == "manager":
            logger.warning(f"Function: suspend_role. Subject {subject_id} attempted to suspend manager role. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Cannot suspend manager role"})), 403
        
        if not session_data:
            logger.warning(f"Function: suspend_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: suspend_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: suspend_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, organization_id)
        if not permissions:
            logger.warning(f"Function: suspend_role. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        if "ROLE_DOWN" not in permissions["org_permissions"]:
            logger.warning(f"Function: suspend_role. Subject {subject_id} does not have permission to suspend a role in the organization. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to suspend a subject"})), 403
        
        findOrganization = query_db("SELECT * FROM Organization WHERE id = ?", (organization_id,), one=True)
        if not findOrganization:
            logger.warning(f"Function: suspend_role. Organization {organization_id} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Organization not found"})), 404

        findRole = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRole:
            logger.warning(f"Function: suspend_role. Role {role_name} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found in the organization"})), 404
        
        isActivated = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ? AND active = TRUE", (role_name, organization_id), one=True)
        if not isActivated:
            logger.warning(f"Function: suspend_role. Role {role_name} is already suspended. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role is already suspended"})), 409

        query_db("UPDATE Role SET active = FALSE WHERE name = ? AND organization_id = ?", (role_name, organization_id), commit=True)

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        logger.info(f"Function: suspend_role. Role {role_name} suspended successfully in organization {organization_id} by subject {subject_id}. Request from address {request.remote_addr}")
        encrypted_response = encrypt("Role %s suspended successfully!" % role_name, session_pub_key)
        return jsonify(signed_payload(encrypted_response)), 200
    
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: suspend_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/role/reactivate", methods=["POST"])
def reactivate_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    
    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: reactivate_role. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: reactivate_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: reactivate_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: reactivate_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: reactivate_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: reactivate_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, organization_id)
        if not permissions:
            logger.warning(f"Function: reactivate_role. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        if "ROLE_UP" not in permissions["org_permissions"]:
            logger.warning(f"Function: reactivate_role. Subject {subject_id} does not have permission to reactivate a role in the organization. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to suspend a subject"})), 403
        
        findOrganization = query_db("SELECT * FROM Organization WHERE id = ?", (organization_id,), one=True)
        if not findOrganization:
            logger.warning(f"Function: reactivate_role. Organization {organization_id} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Organization not found"})), 404

        findRole = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRole:
            logger.warning(f"Function: reactivate_role. Role {role_name} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found in the organization"})), 404
        
        isDeactivated = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ? AND active = FALSE", (role_name, organization_id), one=True)
        if not isDeactivated:
            logger.warning(f"Function: reactivate_role. Role {role_name} is not suspended. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role is not suspended"})), 409

        query_db("UPDATE Role SET active = TRUE WHERE name = ? AND organization_id = ?", (role_name, organization_id), commit=True)

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Role %s reactivated successfully!" % role_name, session_pub_key)
        logger.info(f"Function: reactivate_role. Role {role_name} reactivated successfully in organization {organization_id} by subject {subject_id}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: reactivate_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

@app.route("/role/subject/add", methods=["POST"])
def assume_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    
    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: assume_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: assume_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: assume_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: assume_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: assume_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        findOrganization = query_db("SELECT * FROM Organization WHERE id = ?", (organization_id,), one=True)
        if not findOrganization:
            logger.warning(f"Function: assume_role. Organization {organization_id} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Organization not found"})), 404
        
        isSuspended = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ? AND active = FALSE", (role_name, organization_id), one=True)
        if isSuspended:
            logger.warning(f"Function: assume_role. Role {role_name} is suspended. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role is suspended"})), 409

        isRoleAsssignedToUser = query_db("SELECT * FROM Subject_Role JOIN Role ON Subject_Role.role_id = Role.id WHERE Subject_Role.subject_id = ? AND Role.name = ?", (subject_id, role_name), one=True)
        if isRoleAsssignedToUser is None:
            logger.warning(f"Function: assume_role. Subject {subject_id} does not have role {role_name} assigned. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject doesn't have role %s assigned" % role_name})), 404
        idRole = isRoleAsssignedToUser["role_id"]
        if isRoleAsssignedToUser["assumed"] == 1:
            logger.warning(f"Function: assume_role. Role {role_name} already assumed by subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role already assumed by subject"})), 409
        else:
            query_db("UPDATE Subject_Role SET assumed = 1 WHERE subject_id = ? AND role_id = ?", (subject_id, idRole), commit=True)


        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Role assumed by subject successfully!", session_pub_key)
        logger.info(f"Function: assume_role. Role {role_name} assumed by subject {subject_id} successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: assume_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

    
@app.route("/role/list", methods=["POST"])
def list_roles():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: list_roles. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: list_roles. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403


    if not organization_id or not subject_id:
        logger.warning(f"Function: list_roles. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: list_roles. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: list_roles. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_roles. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403

        subject_roles = query_db("SELECT Role.id FROM Role JOIN Subject_Role ON Role.id = Subject_Role.role_id WHERE Subject_Role.subject_id = ? AND Subject_Role.assumed = '1' AND Role.active = TRUE AND Role.organization_id = ?", (subject_id, organization_id))
        roles_names = []
        for role in subject_roles:
            r_name = query_db("SELECT name FROM Role WHERE id = ?", (role), one=True)
            roles_names.append(r_name["name"])

        payload = {
            "roles_names": roles_names
        }
        
        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(json.dumps(payload), session_pub_key)  
        logger.info(f"Function: list_roles. Roles listed successfully for subject {subject_id}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200

    
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.info(f"Function: list_roles. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/role/subject/list", methods=["POST"])
def list_role_subjects():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    role = data.get("role")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: list_role_subjects. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: list_role_subjects. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403


    if not organization_id or not subject_id:
        logger.warning(f"Function: list_role_subjects. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning (f"Function: list_role_subjects. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: list_role_subjects. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_role_subjects. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403


        role_id = query_db("SELECT id FROM Role WHERE name = ? AND organization_id = ?", (role, organization_id), one=True)

        if not role_id:
            logger.warning(f"Function: list_role_subjects. Role {role} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found"})), 404
        
        role_subjects = query_db("SELECT subject_id FROM Subject_Role WHERE role_id = ?", (role_id["id"],))

        if not role_subjects:
            logger.warning(f"Function: list_role_subjects. Role {role} does not have any subjects. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role does not have any subjects"})), 404
        
        subject_names = []
        for subject in role_subjects:
            s_name = query_db("SELECT username FROM Subject WHERE id = ?", (subject), one=True)
            subject_names.append(s_name["username"])


        payload = {
            "subject_names": subject_names
        }

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(json.dumps(payload), session_pub_key)
        logger.info(f"Function: list_role_subjects. Subjects listed successfully for role {role}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    

    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: list_role_subjects. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500



@app.route("/subject/roles/list", methods=["POST"])
def list_subject_roles():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    username = data.get("username")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: list_subject_roles. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: list_subject_roles. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403


    if not organization_id or not subject_id:
        logger.warning(f"Function: list_subject_roles. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: list_subject_roles. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: list_subject_roles. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_subject_roles. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403



        subject = query_db("SELECT id FROM Subject WHERE username = ?", (username,), one=True)

        if not subject:
            logger.warning(f"Function: list_subject_roles. Subject {username} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject not found"})), 404

        subject_roles = query_db("SELECT role_id FROM Subject_Role JOIN Role ON Subject_Role.role_id = Role.id WHERE Subject_Role.subject_id = ? AND Role.organization_id = ?", (subject["id"], organization_id))
        if not subject_roles:
            logger.warning(f"Function: list_subject_roles. Subject {username} does not have any roles. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any roles"})), 404

        user_roles = []
        for role in subject_roles:
            r_name = query_db("SELECT name FROM Role WHERE id = ?", (role["role_id"],), one=True)
            if r_name:
                user_roles.append(r_name["name"])
        
        payload = {
            "user_roles": user_roles
        }

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(json.dumps(payload), session_pub_key)
        logger.info(f"Function: list_subject_roles. Roles listed successfully for subject {username}. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    
        

    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: list_subject_roles. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/role/subject/drop", methods=["POST"])
def rep_drop_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: rep_drop_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: rep_drop_role. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: rep_drop_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: rep_drop_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: rep_drop_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: rep_drop_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403


        findRoleToDrop = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRoleToDrop:
            return jsonify(signed_payload({"error": "Role not found"})), 404        
        else:
            role_id = findRoleToDrop["id"]
            role_subjects = query_db("SELECT * FROM Subject_Role WHERE role_id = ? AND subject_id = ?", (role_id, subject_id), one=True)
            if not role_subjects:
                logger.warning(f"Function: rep_drop_role. Role {role_name} does not have any subjects. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Role does not have any subjects"})), 404
            if role_subjects["assumed"] == 0:
                logger.warning(f"Function: rep_drop_role. Role {role_name} already dropped from subject {subject_id}. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Role already dropped from subject"})), 409
            query_db("UPDATE Subject_Role SET assumed = 0 WHERE role_id = ? AND subject_id = ?", (role_id, subject_id), commit=True)

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Role removed from subject successfully!", session_pub_key)
        logger.info(f"Function: rep_drop_role. Role {role_name} removed from subject {subject_id} successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: rep_drop_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500

@app.route("/role/permission/add", methods=["POST"])
def rep_add_permission_to_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    permission = data.get("permission")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: rep_add_permission_to_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: rep_add_permission_to_role. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: rep_add_permission_to_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: rep_add_permission_to_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: rep_add_permission_to_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403
        
        permissions = check_permissions(subject_id, organization_id)

        if "ROLE_MOD" not in permissions["org_permissions"]:
            logger.warning(f"Function: rep_add_permission_to_role. Subject {subject_id} does not have permission to add permission to a role. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to add permission to a role"})), 403
        

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: rep_add_permission_to_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403

            
        findRoleToAdd = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRoleToAdd:
            logger.warning(f"Function: rep_add_permission_to_role. Role {role_name} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found"})), 404
        findPermission = query_db("SELECT * FROM Perms WHERE name = ?", (permission,), one=True)
        if not findPermission:
            logger.warning(f"Function: rep_add_permission_to_role. Permission {permission} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Permission not found"})), 404
        
        query_db("INSERT INTO Role_Perms (role_id, perm_id) VALUES (?, ?)", (findRoleToAdd["id"], findPermission["id"]), commit=True)

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Permission %s added to role %s successfully!" % (permission, role_name), session_pub_key)
        logger.info(f"Function: rep_add_permission_to_role. Permission {permission} added to role {role_name} successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: rep_add_permission_to_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/user/role/add", methods=["POST"])
def rep_add_permission_to_user():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    username = data.get("username")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: rep_add_permission_to_user. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: rep_add_permission_to_user. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: rep_add_permission_to_user. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")


        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: rep_add_permission_to_user. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: rep_add_permission_to_user. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403
        
        permissions = check_permissions(subject_id, organization_id)

        if "ROLE_MOD" not in permissions["org_permissions"]:
            logger.warning(f"Function: rep_add_permission_to_user. Subject {subject_id} does not have permission to add role to user. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to add role to user"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: rep_add_permission_to_user. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403

            
        findRoleToAdd = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRoleToAdd:
            logger.warning(f"Function: rep_add_permission_to_user. Role {role_name} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found"})), 404        
        findIfSubjectExists = query_db("SELECT * FROM Subject WHERE username = ?", (username,), one=True)

        if not findIfSubjectExists:
            logger.warning(f"Function: rep_add_permission_to_user. Subject {username} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject not found"})), 404

        existingRole = query_db(
            "SELECT * FROM Subject_Role WHERE subject_id = ? AND role_id = ?",
            (findIfSubjectExists["id"], findRoleToAdd["id"]),
            one=True
        )

        if existingRole:
            logger.warning(f"Function: rep_add_permission_to_user. Subject {username} already has role {role_name}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject already has this role"})), 400
        print("OLAAAA")
        print(findIfSubjectExists["id"])
        print(findRoleToAdd["id"])
        query_db(
            "INSERT INTO Subject_Role (subject_id, role_id) VALUES (?, ?)",
            (findIfSubjectExists["id"], findRoleToAdd["id"]),
            commit=True
        )
        
        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Role %s added to user %s successfully!" % (role_name, username), session_pub_key)
        logger.info(f"Function: rep_add_permission_to_user. Role {role_name} added to user {username} successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: rep_add_permission_to_user. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500



@app.route("/role/permission/remove", methods=["POST"])
def rep_remove_permission_from_role():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    permission = data.get("permission")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: rep_remove_permission_from_role. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: rep_remove_permission_from_role. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: rep_remove_permission_from_role. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        if role_name.lower() == "manager":
            logger.warning(f"Function: rep_remove_permission_from_role. Cannot remove permission from Manager role. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Cannot remove permission from Manager role"})), 403
        
        permissions = check_permissions(subject_id, organization_id)
        if not permissions:
            logger.warning(f"Function: rep_remove_permission_from_role. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: rep_remove_permission_from_role. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: rep_remove_permission_from_role. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403
        
        permissions = check_permissions(subject_id, organization_id)

        if "ROLE_MOD" not in permissions["org_permissions"]:
            logger.warning(f"Function: rep_remove_permission_from_role. Subject {subject_id} does not have permission to remove permission from role. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to remove permission from role"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: rep_remove_permission_from_role. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403

            
        findRoleToRemovePermission = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRoleToRemovePermission:
            logger.warning(f"Function: rep_remove_permission_from_role. Role {role_name} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found"})), 404
        findPermission = query_db("SELECT * FROM Perms WHERE name = ?", (permission,), one=True)
        if not findPermission:
            logger.warning(f"Function: rep_remove_permission_from_role. Permission {permission} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Permission not found"})), 404
        
        findIfRoleHasPermission = query_db("SELECT * FROM Role_Perms WHERE role_id = ? AND perm_id = ?", (findRoleToRemovePermission["id"], findPermission["id"]), one=True)
        if not findIfRoleHasPermission:
            logger.warning(f"Function: rep_remove_permission_from_role. Role {role_name} does not have permission {permission}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role does not have this permission"})), 404
        
        query_db("DELETE FROM Role_Perms WHERE role_id = ? AND perm_id = ?", (findRoleToRemovePermission["id"], findPermission["id"]), commit=True)

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Permission %s removed from role %s successfully!" % (permission, role_name), session_pub_key)
        logger.info(f"Function: rep_remove_permission_from_role. Permission {permission} removed from role {role_name} successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: rep_remove_permission_from_role. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/user/role/remove", methods=["POST"])
def rep_remove_permission_from_user():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    role_name = data.get("role")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    username = data.get("username")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: rep_remove_permission_from_user. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: rep_remove_permission_from_user. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: rep_remove_permission_from_user. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: rep_remove_permission_from_user. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: rep_remove_permission_from_user. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403
        
        permissions = check_permissions(subject_id, organization_id)

        if "ROLE_MOD" not in permissions["org_permissions"]:
            logger.warning(f"Function: rep_remove_permission_from_user. Subject {subject_id} does not have permission to remove role from user. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to remove role from user"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: rep_remove_permission_from_user. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403

            
        findRoleToRemove = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role_name, organization_id), one=True)
        if not findRoleToRemove:
            logger.warning(f"Function: rep_remove_permission_from_user. Role {role_name} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found"})), 404        
        findIfSubjectExists = query_db("SELECT * FROM Subject WHERE username = ?", (username,), one=True)
        if role_name.lower() == "manager":
            numManager = query_db("""
                SELECT COUNT(*) AS manager_count 
                FROM Subject_Role 
                WHERE role_id = (
                    SELECT id FROM Role WHERE organization_id = ? AND name = 'Manager'
                )
            """, (organization_id,), one=True)
            if numManager == 1:
                logger.warning(f"Function: rep_remove_permission_from_user. Cannot remove Manager role. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Cannot remove Manager role"})), 403
        if not findIfSubjectExists:
            logger.warning(f"Function: rep_remove_permission_from_user. Subject {username} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject not found"})), 404
    
        existingRole = query_db(
            "SELECT * FROM Subject_Role WHERE subject_id = ? AND role_id = ?",
            (findIfSubjectExists["id"], findRoleToRemove["id"]),
            one=True
        )

        if not existingRole:
            logger.warning(f"Function: rep_remove_permission_from_user. Subject {username} does not have role {role_name}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have this role"})), 400
                
        query_db(
            "DELETE FROM Subject_Role WHERE subject_id = ? AND role_id = ?",
            (findIfSubjectExists["id"], findRoleToRemove["id"]),
            commit=True
        )
        
        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt("Role %s removed from user %s successfully!" % (role_name, username), session_pub_key)
        logger.info(f"Function: rep_remove_permission_from_user. Role {role_name} removed from user {username} successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: rep_remove_permission_from_user. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


@app.route("/role/permissions/list", methods=["POST"])
def list_role_permissions():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    role = data.get("role")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: list_role_permissions. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: list_role_permissions. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403


    if not organization_id or not subject_id:
        logger.warning(f"Function: list_role_permissions. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: list_role_permissions. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: list_role_permissions. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_role_permissions. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403


        role_permissions = {"org": [], "docs": {}}

        role_id = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role, organization_id), one=True)

        if not role_id:
            return jsonify(signed_payload({"error": "Role not found"})), 404        
        organization_permissions = query_db("SELECT * FROM Role")
        organization_permissions = [perm["id"] for perm in organization_permissions]
        
        if role_id["id"] in organization_permissions:
            perm_roles= query_db("SELECT perm_id FROM Role_Perms WHERE role_id = ?", (role_id["id"],))
            for perm in perm_roles:
                p_name = query_db("SELECT name FROM Perms WHERE id = ?", (perm["perm_id"],), one=True)
                if p_name:
                    role_permissions["org"].append(p_name["name"])

        
        documents = query_db("SELECT d_handle, name FROM Document WHERE organization_id = ?", (organization_id,))

        for doc in documents:
            doc_perm = query_db("SELECT perm_id FROM Role_Doc_Perms WHERE role_id = ? AND d_handle = ?", (role_id["id"], doc["d_handle"]))
            for perm in doc_perm:
                p_name = query_db("SELECT name FROM Perms WHERE id = ?", (perm["perm_id"],), one=True)
                if p_name:
                    if doc["name"] not in role_permissions["docs"]:
                        role_permissions["docs"][doc["name"]] = []
                    role_permissions["docs"][doc["name"]].append(p_name["name"])
        
        role_permissions["org"] = [
        perm for perm in role_permissions["org"] if perm not in ["DOC_READ", "DOC_ACL", "DOC_DELETE"]
        ]
                
        payload = {
            "role_permissions": role_permissions
        }

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(json.dumps(payload), session_pub_key)
        logger.info(f"Function: list_role_permissions. Role {role} permissions listed successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200

        
        

    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: list_role_permissions. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500



@app.route("/permission/roles/list", methods=["POST"])
def list_permission_roles():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization")
    subject_id = data.get("subject")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    permission = data.get("permission")

    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: list_permission_roles. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: list_permission_roles. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403


    if not organization_id or not subject_id:
        logger.warning(f"Function: list_permission_roles. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")
        session_data = query_db(
            "SELECT last_interaction, keys FROM Session WHERE subject_id = ? AND organization_id = ?",
            (subject_id, organization_id),
            one=True
        )

        if not session_data:
            logger.warning(f"Function: list_permission_roles. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404
        
        keys = session_data["keys"].split("\n--other-key--\n")
        if not unpack_signed_payload(request.json, keys[0]):
            logger.critical(f"Function: list_permission_roles. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid authentication"})), 403

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: list_permission_roles. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403


        perm_id = query_db("SELECT id FROM Perms WHERE name = ?", (permission,), one=True)
        perm_id = perm_id["id"]

        if not perm_id:
            logger.warning(f"Function: list_permission_roles. Permission {permission} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Permission not found"})), 404
        

        roles_org = []
        roles_doc = {}

        organization_roles = query_db("SELECT role_id, perm_id FROM Role_Perms JOIN Role ON Role_Perms.role_id = Role.id WHERE Role.organization_id = ?", (organization_id,))
    
        for role in organization_roles:
            if role["perm_id"] == perm_id:
                r_name = query_db("SELECT name FROM Role WHERE id = ?", (role["role_id"],), one=True)
                if r_name:
                    roles_org.append(r_name["name"])

        payload = {
            "roles_org": roles_org
        }

        documents = query_db("SELECT d_handle, name FROM Document WHERE organization_id = ?", (organization_id,))

        for doc in documents:
            doc_roles = query_db("SELECT role_id, perm_id FROM Role_Doc_Perms WHERE d_handle = ?", (doc["d_handle"],))

            for role in doc_roles:
                if role["perm_id"] == perm_id:
                    r_name = query_db("SELECT name FROM Role WHERE id = ?", (role["role_id"],), one=True)
                    if r_name:
                        if doc["name"] not in roles_doc:
                            roles_doc[doc["name"]] = []
                        roles_doc[doc["name"]].append(r_name["name"])

        payload["roles_doc"] = roles_doc

        conn.commit()
        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        encrypted_response = encrypt(json.dumps(payload), session_pub_key)
        logger.info(f"Function: list_permission_roles. Permission {permission} roles listed successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    

    

    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: list_permission_roles. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500



@app.route("/docs/acl", methods=["POST"])
def modify_doc_acl():
    data = json.loads(decrypt(request.json["payload"], PRIVATEKEY))
    organization_id = data.get("organization_id")
    subject_id = data.get("subject_id")
    document_name = data.get("document_name")
    role = data.get("role")
    adding = data.get("adding")
    nonce = data.get("nonce")
    seq_number = data.get("seq_number")
    signature = data.get("signature")
    permission= data.get("permission")
    
    if not verify_nonce(subject_id, organization_id, nonce) or not verify_sequential_number(subject_id, organization_id, seq_number):
        logger.warning(f"Function: modify_doc_acl. Subject {subject_id} failed to authenticate. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid nonce or sequence number. Woop woop that's the sound of the police!"})), 403

    if not verify_signature(subject_id, organization_id, signature):
        logger.critical(f"Function: modify_doc_acl. Subject {subject_id} failed to authenticate, likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Authentication failed"})), 403

    if not organization_id or not subject_id:
        logger.warning(f"Function: modify_doc_acl. Missing required fields (organization_id, subject_id). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session data"})), 400
    
    # check signature
    session_data = query_db(
        "SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?",
        (subject_id, organization_id),
        one=True
    )

        
    if not session_data:
        logger.warning(f"Function: modify_doc_acl. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid session"})), 404
    
    keys = session_data["keys"].split("\n--other-key--\n")
    if not unpack_signed_payload(request.json, keys[0]):
        logger.critical(f"Function: modify_doc_acl. Subject {subject_id} is likely compromised (invalid subject signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid authentication"})), 403
    

    session_pub_key = session_data["keys"].split("\n--other-key--\n")[0]
    if not session_pub_key:
        logger.warning(f"Function: modify_doc_acl. Subject {subject_id} does not have a public key. Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Subject not found"})), 404
    if not unpack_signed_payload(request.json, session_pub_key):
        logger.critical(f"Function: modify_doc_acl. Subject {subject_id} is likely compromised (invalid session signature). Request from address {request.remote_addr}")
        return jsonify(signed_payload({"error": "Invalid authentication"})), 403


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
            logger.warning(f"Function: modify_doc_acl. Invalid session for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Invalid session"})), 404

        last_interaction = session_data["last_interaction"]
        current_time = time.time()

        if current_time - last_interaction > SESSION_LIFETIME:
            session = query_db("SELECT * FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
            query_db("DELETE FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), commit=True)
            query_db("DELETE FROM Nonce WHERE session_id = ?", (session["id"],), commit=True)
            
            expired_seconds = current_time - last_interaction
            expired_seconds = round(expired_seconds, 0)
            logger.warning(f"Function: modify_doc_acl. Session expired {expired_seconds} seconds ago for subject {subject_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": f"Session expired {expired_seconds} seconds ago"})), 403
        
        permissions = check_permissions(subject_id, organization_id)
        if not permissions:
            logger.warning(f"Function: modify_doc_acl. Subject {subject_id} does not have any permissions. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have any permissions"})), 403

        document_permissions = permissions.get("doc_permissions", {})
        doc_permissions = document_permissions.get(document_name)

        if not doc_permissions:
            logger.warning(f"Function: modify_doc_acl. Subject {subject_id} does not have permission to access this document. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to access this document"})), 403
        
        if "DOC_ACL" not in doc_permissions:
            logger.warning(f"Function: modify_doc_acl. Subject {subject_id} does not have permission to modify document ACL. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Subject does not have permission to read this document"})), 403
        
        findOrganization = query_db("SELECT * FROM Organization WHERE id = ?", (organization_id,), one=True)
        if not findOrganization:
            logger.warning(f"Function: modify_doc_acl. Organization {organization_id} not found. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Organization not found"})), 404
        
        findDocument = query_db("SELECT * FROM Document WHERE name = ? AND organization_id = ?", (document_name, organization_id), one=True)
        if not findDocument:
            logger.warning(f"Function: modify_doc_acl. Document {document_name} not found in the organization. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Document not found in the organization"})), 404


        #insert permission in Role_Doc_Perms table
        findRole = query_db("SELECT * FROM Role WHERE name = ? AND organization_id = ?", (role, organization_id), one=True)
        if not findRole:
            logger.warning(f"Function: modify_doc_acl. Role {role} not found in organization {organization_id}. Request from address {request.remote_addr}")
            return jsonify(signed_payload({"error": "Role not found"})), 404
        
        role_id = findRole["id"]
        print(role_id)
        print(findRole["name"])

        permAdded = query_db("SELECT * FROM Perms WHERE name = ?", (permission,), one=True)

        if adding:
            query_db("INSERT INTO Role_Doc_Perms (role_id, d_handle, perm_id) VALUES (?, ?, ?)", (role_id, findDocument["d_handle"], permAdded["id"]), commit=True)
        else:
            if role.lower() == "manager":
                logger.warning(f"Function: modify_doc_acl. Cannot remove permission from Manager role. Request from address {request.remote_addr}")
                return jsonify(signed_payload({"error": "Cannot remove permission from Manager role"})), 403
            else:
                query_db("DELETE FROM Role_Doc_Perms WHERE role_id = ? AND d_handle = ? AND perm_id = ?", (role_id, findDocument["d_handle"], permAdded["id"]), commit=True)
           
        conn.commit()

        session_pub_key = query_db("SELECT keys FROM Session WHERE subject_id = ? AND organization_id = ?", (subject_id, organization_id), one=True)
        session_pub_key = session_pub_key["keys"].replace("\\n", "\n")
        if adding:
            encrypted_response = encrypt("Document ACL modified successfully, permission %s added to role %s in respect of document %s" % (permission, role, document_name), session_pub_key)
        else:
            encrypted_response = encrypt("Document ACL modified successfully, permission %s removed from role %s in respect of document %s" % (permission, role, document_name), session_pub_key)
        logger.info(f"Function: modify_doc_acl. Document ACL modified successfully. Request from address {request.remote_addr}")
        return jsonify(signed_payload(encrypted_response)), 200
    
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        logger.error(f"Function: modify_doc_acl. With payload {data}: {e}")
        return jsonify(signed_payload({"error": f"An error occurred: {e}"})), 500


def checkpassword():
    attempted_password = input("Insert password for database: ")
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(attempted_password.encode())
    d = digest.finalize()

    if d == MASTERKEY:
        logger.info("Password correct")
        return
    logger.warning("Password incorrect")
    checkpassword()

if __name__ == "__main__":
    load_dotenv()
    PUBLICKEY=os.getenv('PUBLIC_KEY')
    PRIVATEKEY=os.getenv('PRIVATE_KEY')

    checkpassword()
    app.run(debug=True)