#!/usr/bin/env python3
import base64
import hashlib
import os
import sys
import argparse
import logging
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from encrypt_comms import encrypt, decrypt
from dotenv import load_dotenv

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

load_dotenv()
REP_PUB_KEY = os.getenv('PUBLIC_KEY')


def signed_payload(payload: dict, private_key: str) -> dict:
    rep_private_key = serialization.load_pem_private_key(private_key.encode(), password=None)
    signed_payload = rep_private_key.sign(
        json.dumps(payload, sort_keys=True).encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {"payload": payload, "signature": signed_payload.hex()}

def unpack_signed_payload(signed_payload: dict, public_key: str = None) -> dict:
    if public_key is None:
        public_key = REP_PUB_KEY
    rep_pub_key = serialization.load_pem_public_key(public_key.encode())
    response = signed_payload.get("response")
    
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
        print(f"An error occurred: {e}")
        sys.exit(1)
    return response

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

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)
    
    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        state['REP_PUB_KEY'] = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(state['REP_PUB_KEY']):
            with open(state['REP_PUB_KEY'], 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    else:
        logger.debug('REP_PUB_KEY not set in environment')
    
    return state


def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)
        
        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')
    return state

        
def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

def subject_credentials(password, credentials_file):
    private_key = ec.generate_private_key(ec.SECP521R1())

    password_bytes = password.encode()  

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )

    with open(credentials_file, 'wb') as priv_file:
        priv_file.write(encrypted_private_key)

    public_key = private_key.public_key()
    public_key_file = credentials_file.replace(".pem", "_public.pem")
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("ECC key pair generated successfully.")
    print(f"Encrypted private key saved to {credentials_file}")
    print(f"Public key saved to {public_key_file}")

def decrypt_file(encrypted_file_path, metadata_path):
    try:
        with open(metadata_path, 'r') as meta_file:
            metadata = json.load(meta_file)
        
        alg = metadata.get('alg')
        password = metadata.get('password')
        expected_digest = metadata.get('f_handle')

        if not alg or not password:
            print("Error: Invalid metadata file. Missing 'alg' or 'password'.")
            sys.exit(1)

        alg_parts = alg.split('|')
        if len(alg_parts) != 5 or alg_parts[0] != "SHA256" or alg_parts[1] != "AES-GCM":
            print("Error: Unsupported or invalid encryption algorithm in metadata.")
            sys.exit(1)

        salt = bytes.fromhex(alg_parts[2])
        nonce = bytes.fromhex(alg_parts[3])
        tag = bytes.fromhex(alg_parts[4])

        derived_key = derive_key(password, salt)

        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_content = enc_file.read()

        print("Encrypted Content:", encrypted_content)
        newDigest = hashlib.sha256(encrypted_content).digest()
        newDigest = base64.b64encode(newDigest).decode('utf-8')
        
        print("\n")

        if newDigest != expected_digest:
            print("Error: File integrity check failed.")
            sys.exit(1)

        ciphertext_with_tag = encrypted_content + tag

        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        print(plaintext.decode('utf-8'))

    except FileNotFoundError:
        print("Error: One or more files not found.")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: Metadata file is not valid JSON.")
        sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def add_doc(session_file, document_name, file_path):

    API_ENDPOINT = "http://127.0.0.1:5000/document/create"

    with open(session_file, "r") as f:
        session_data = json.load(f)
    
    organization_id = session_data.get("organization_id")
    subject_id = session_data.get("subject_id")
    private_key_path = session_data.get("PRIV_KEY")
    seq_number = session_data.get("seq_number")
    with open(private_key_path, "r") as f:
        private_key = f.read()
    rep_pub_key = session_data.get("REP_PUB_KEY")
    payload = {
        "document_name": document_name,
        "file_path": file_path,
        "organization_id": organization_id,
        "subject_id": subject_id,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": session_data.get("signature")
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)
    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            print("Response:", decrypt(payload, private_key))

        else:
            print(f"Failed to create document. Status Code: {response.status_code}")
            print("Response:", payload)

        sys.exit(0)
    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def add_subject(session_file_name, username, name, email, public_key_file):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")
    with open(private_key_path, "r") as f:
        private_key = f.read()
    try:
        with open(public_key_file, 'rb') as key_file:
            public_key = key_file.read().decode('utf-8')
    except FileNotFoundError:
        print(f"Error: The file '{public_key_file}' was not found.")
        sys.exit(1)


    API_ENDPOINT = "http://127.0.0.1:5000/organization/subject"

    payload = {
        "organization": organization,
        "subject": subject,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            print("Response:", decrypt(payload, private_key))

            sys.exit(0)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def create_organization(organization, username, name, email, public_key_file):
    try:
        with open(public_key_file, 'rb') as key_file:
            public_key = key_file.read().decode('utf-8')
    except FileNotFoundError:
        print(f"Error: The file '{public_key_file}' was not found.")
        sys.exit(1)

    API_ENDPOINT = "http://127.0.0.1:5000/organization/create"
    
    payload = {
        "organization": organization,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)

    try:
        response_whole = requests.post(API_ENDPOINT, json=encrypted_payload)
        response = unpack_signed_payload(response_whole.json(), REP_PUB_KEY)

        if response_whole.status_code == 200:
            print("Response:", response)
        else:
            print(f"Failed to create organization. Status Code: {response_whole.status_code}")
            print("Response:", response)

        sys.exit(0)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def create_session(organization, username, password, credentials_file, session_file_name):
    AUTH_ENDPOINT = "http://127.0.0.1:5000/session/authenticate"
    API_ENDPOINT = "http://127.0.0.1:5000/session/create"

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(2048)
    )

    with open(credentials_file, 'rb') as f:
        private_key_subject = serialization.load_pem_private_key(
            f.read(),
            password=password.encode(),
            backend=default_backend()
        )
        private_key_subject_pem = private_key_subject.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    public_key = private_key_subject.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {
        "organization": organization,
        "username": username,
        "pubkey": public_key_pem.decode(),
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    
    try:
        response_whole = requests.post(AUTH_ENDPOINT, json=encrypted_payload)
        payload = unpack_signed_payload(response_whole.json(), REP_PUB_KEY)

        if response_whole.status_code == 200:
            encrypted_challenge = payload.get("challenge")
            rep_pub_key = payload.get("rep_pub_key")
            if encrypted_challenge is None or rep_pub_key is None:
                print("Error: Missing challenge in response.")
                sys.exit(-1)
            challenge = decrypt(encrypted_challenge, private_key_subject_pem.decode())
        elif response_whole.status_code == 401:
            print("Error: Unauthorized. Check your credentials.")
            sys.exit(-1)
        elif response_whole.status_code == 500:
            print("Error: Internal server error: ", payload)
            sys.exit(-1)
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        sys.exit(-1)



    public_key = private_key.public_key()
    public_key_name = username + "_" + organization + "_public.pem"
    private_key_name = username + "_" + organization + "_private.pem"

    with open(public_key_name, 'wb') as pubKey:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem.splitlines()[0]
        pubKey.write(pem)

    with open(private_key_name, 'wb') as privKey:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pem.splitlines()[0]
        privKey.write(pem)

    with open(public_key_name, 'rb') as key_file:
        public_key = key_file.read().decode('utf-8')

    try:
        payload = {
            "organization": organization,
            "username": username,
            "public_key": public_key,
            "challenge": encrypt(challenge, rep_pub_key),
        }
        encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    try:
        response_whole = requests.post(API_ENDPOINT, json=encrypted_payload)
        payload = unpack_signed_payload(response_whole.json(), REP_PUB_KEY)

        if response_whole.status_code == 200:
            session_data = payload.get("session_data", {})

            with open(session_file_name, 'w') as f:
                session_data["PRIV_KEY"] = private_key_name
                session_data["seq_number"] = 0
                json.dump(session_data, f, indent=4)
            print("Session created successfully, session file in", session_file_name)
        else:
            print(f"Failed to create session. Status Code: {response_whole.status_code}")
            print("Response:", payload)

        sys.exit(0)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def delete_document(session_file, document_name):

    API_ENDPOINT = "http://127.0.0.1:5000/document/delete"

    with open(session_file, "r") as f:
        session_data = json.load(f)
    private_key_path = session_data["PRIV_KEY"]
    with open(private_key_path, "r") as f:
        private_key = f.read()

    payload = {
        "subject_id": session_data["subject_id"],
        "organization_id": session_data["organization_id"],
        "document_name": document_name,
        "nonce": os.urandom(16).hex(),
        "seq_number": session_data["seq_number"],
        "signature": session_data["signature"]
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)
    try:
        response = requests.delete(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            print("Document deleted successfully.")
            print(decrypt(payload, private_key))
        else:
            print(f"Error deleting document: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        sys.exit(1)

def get_doc_file(session_file, document_name, output_file=None):

    API_ENDPOINT = "http://127.0.0.1:5000/document/file"

    try :
        with open(session_file, "r") as f:
            session_data = json.load(f)
        private_key_path = session_data["PRIV_KEY"]
        with open(private_key_path, "r") as f:
            private_key = f.read()
        rep_pub_key = session_data["REP_PUB_KEY"]

        if "organization_id" not in session_data or "subject_id" not in session_data:
            print("Error: Missing required fields in session file.")
            sys.exit(1)

        payload = {
            "organization_id": session_data["organization_id"],
            "subject_id": session_data["subject_id"],
            "document_name": document_name,
            "nonce": os.urandom(16).hex(),
            "seq_number": session_data["seq_number"],
            "signature": session_data["signature"]
        }

        encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
        signed_payload_ = signed_payload(encrypted_payload, private_key)
        with open(session_file, "w") as session_file:
            session_data["seq_number"] += 1
            json.dump(session_data, session_file, indent=4)

    except FileNotFoundError:
        print("Error: Session file not found.")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: Session file is not valid JSON.")
        sys.exit(1)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            file_data = json.loads(decrypt(payload, private_key))
            file_content = file_data.get("content", "").encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')

            if output_file:
                try:
                    with open(output_file, "w", encoding="utf-8") as f:
                        f.write(file_content)
                    print(f"File content successfully saved to {output_file}")
                except IOError as e:
                    print(f"Error writing to file: {e}")
                    sys.exit(1)
            else:
                print("File content:\n", file_content)

        elif response.status_code == 400:
            print("Error: Missing required fields.")
        elif response.status_code == 403:
            print(payload)
        else:
            print(f"Error: Received unexpected status code {response.status_code}")
            print(payload)

    except FileNotFoundError:
        print("Error: Session file not found.")

    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to the API. {e}")

def rep_get_doc_metadata(session_file, document_name):

    METADATA_ENDPOINT = "http://127.0.0.1:5000/document/metadata"

    try:
        with open(session_file, "r") as f:
            session_data = json.load(f)
        private_key_path = session_data["PRIV_KEY"]
        with open(private_key_path, "r") as f:
            private_key = f.read()
        rep_pub_key = session_data["REP_PUB_KEY"]

        if "organization_id" not in session_data or "subject_id" not in session_data:
            print("Error: Missing required fields in session file.")
            sys.exit(1)
        
        payload = {
            "organization_id": session_data["organization_id"],
            "subject_id": session_data["subject_id"],
            "document_name": document_name,
            "nonce": os.urandom(16).hex(),
            "seq_number": session_data["seq_number"],
            "signature": session_data["signature"]
        }

        encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
        signed_payload_ = signed_payload(encrypted_payload, private_key)
        response = requests.post(METADATA_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        with open(session_file, "w") as session_file:
            session_data["seq_number"] += 1
            json.dump(session_data, session_file, indent=4)
        if response.status_code == 200:
            metadata = decrypt(payload, private_key)

            print("Document metadata:", metadata)
        elif response.status_code == 400:
            print("Error: Missing required fields.")
        elif response.status_code == 403:
            print(f"Error: Received unexpected status code {response.status_code}")
            print(payload)

    except FileNotFoundError:
        print("Error: Session file not found.")

    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to connect to the API. {e}")

def get_file(file_handle, output_filename=None):
    url = "http://127.0.0.1:5000/file"

    payload = {
        "file_handle": file_handle,
    }
        
    response = requests.get(url, params=payload)
    payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
    if response.status_code == 200:
        print("File metadata:", json.dumps(payload, indent=4))

        try:
            file_content = base64.b64decode(payload["content"])
        except base64.binascii.Error:
            print("Error: Failed to decode file content.")
            sys.exit(1)

        if output_filename:
            try:
                with open(output_filename, "wb") as f:
                    f.write(file_content)
                print(f"File content successfully saved to {output_filename}")
            except IOError as e:
                print(f"Error writing to file: {e}")
                sys.exit(1)
        else:
            print("File content:\n", file_content.decode('utf-8', errors='ignore'))
    else:
        print("Error:", json.dumps(payload, indent=4))

def list_docs(params, private_key, rep_public_key, session_file, session_data):
    url = "http://127.0.0.1:5000/docs/list"
    encrypted_payload = encrypt(json.dumps(params), rep_public_key)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)
    response = requests.post(url, json=signed_payload_)
    payload = unpack_signed_payload(response.json(), rep_public_key)    
    try:
        response.raise_for_status()
        documents = decrypt(payload, private_key)

        print("Documents:", documents)
    except requests.exceptions.HTTPError as http_err:
        print("Response content:", payload)
    except requests.exceptions.JSONDecodeError:
        print("Response content:", payload)
    except Exception as err:
        print(f"An error occurred: {err}")

def list_orgs():
    url = "http://127.0.0.1:5000/organization/list" 

    response = requests.get(url)
    payload = unpack_signed_payload(response.json(), REP_PUB_KEY)

    if response.status_code == 200:
        print("Organizations:", payload)
    else:
        print("Error:", payload)
    
def list_subjects(session_file, username):
    url = "http://127.0.0.1:5000/subject/list" 

    with open(session_file, "r") as f:
        session_data = json.load(f)
    
    organization_id = session_data.get("organization_id")
    subject_id = session_data.get("subject_id")
    rep_pub_key = session_data.get("REP_PUB_KEY")
    private_key_path = session_data.get("PRIV_KEY")
    signature = session_data.get("signature")
    with open(private_key_path, "r") as f:
        private_key = f.read()

    payload = {
        "username": username,
        "organization_id": organization_id,
        "subject_id": subject_id,
        "nonce": os.urandom(16).hex(),
        "seq_number": session_data.get("seq_number"),
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)

    with open(session_file, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(url, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            subjects = decrypt(payload, private_key)
            print("Subjects:", subjects)
        else:
            print("Error:", payload)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


def acl_doc(session_file, document_name, role, permission, adding=True):
    API_ENDPOINT = "http://127.0.0.1:5000/docs/acl"

    with open(session_file, "r") as session_file_reader:
        session_data = json.load(session_file_reader)

    rep_pub_key = REP_PUB_KEY
    private_key_path = session_data["PRIV_KEY"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()
        
    payload = {
        "organization_id": session_data["organization_id"],
        "subject_id": session_data["subject_id"],
        "document_name": document_name,
        "role": role,
        "permission": permission,
        "adding": adding,
        "nonce": os.urandom(16).hex(),
        "seq_number": session_data.get("seq_number"),
        "signature": signature
    }


    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)

    with open(session_file, "w") as session_file_writer:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file_writer, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            print("Response:", decrypt(payload, private_key))
            sys.exit(0)
        else:
            print(f"Failed to activate subject. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        


    

def activate_subject(session_file_name, username, organization, subject, session_data):

    with open(session_file_name, "r") as session_file:
        session_data = json.load(session_file)

    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/organization/subject/activate"
    payload = {
        "organization": organization,
        "subject": subject,
        "username": username,
        "nonce": os.urandom(16).hex(),
        "seq_number": session_data.get("seq_number"),
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            print("Response:", decrypt(payload, private_key))
            sys.exit(0)
        else:
            print(f"Failed to activate subject. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)


    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def suspend_subject(session_file_name, username, organization, subject, session_data):
    API_ENDPOINT = "http://127.0.0.1:5000/organization/subject/suspend"

    with open(session_file_name, "r") as session_file:
        session_data = json.load(session_file)

    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    with open(private_key_path, "r") as f:
        private_key = f.read()

    payload = {
        "organization": organization,
        "subject": subject,
        "username": username,
        "nonce": os.urandom(16).hex(),
        "seq_number": session_data.get("seq_number"),
        "signature": session_data.get("signature")
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)
    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            print("Response:", decrypt(payload, private_key))
            sys.exit(0)
        else:
            print(f"Failed to suspend subject. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)


    except requests.RequestException as e:
        print(f"An error occurred: {e}")


#### 2º entrega
def add_role(session_file_name, role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/add"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to add role. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def suspend_role(session_file_name, role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/suspend"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def reactivate_role(session_file_name, role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/reactivate"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def assume_role(session_file_name, role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/subject/add"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to add role to subject. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def list_roles(session_file_name):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/list"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to list all roles. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def list_role_subjects(session_file_name,role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")
    role = role

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/subject/list"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": signature,
        "role": role
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to list all roles. Status Code: {response.status_code}")
            print("Response:", response.text)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def list_subject_roles(session_file_name, username):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")
    username = username

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/subject/roles/list"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": signature,
        "username": username
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to list all roles. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


def list_role_permissions(session_file_name, role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")
    role = role

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/permissions/list"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": signature,
        "role": role
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to list all roles. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


def list_permission_roles(session_file_name, permission):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")
    permission = permission

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/permission/roles/list"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "signature": signature,
        "permission": permission
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print(f"Failed to list all roles. Status Code: {response.status_code}")
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


def drop_role(session_file_name, role):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/subject/drop"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def add_permission_role(session_file_name, role, permission):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/permission/add"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature,
        "permission": permission
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def add_permission_user(session_file_name, role, username):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/user/role/add"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature,
        "username": username
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def remove_permission_role(session_file_name, role, permission):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/role/permission/remove"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature,
        "permission": permission
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")


def remove_permission_user(session_file_name, role, username):
    with open(session_file_name, "r") as session_file:
        session_data = json.loads(session_file.read())

    organization = session_data["organization_id"]
    subject = session_data["subject_id"]
    rep_pub_key = session_data["REP_PUB_KEY"]
    private_key_path = session_data["PRIV_KEY"]
    seq_number = session_data["seq_number"]
    signature = session_data.get("signature")

    with open(private_key_path, "r") as f:
        private_key = f.read()

    API_ENDPOINT = "http://127.0.0.1:5000/user/role/remove"

    payload = {
        "organization": organization,
        "subject": subject,
        "nonce": os.urandom(16).hex(),
        "seq_number": seq_number,
        "role": role,
        "signature": signature,
        "username": username
    }

    encrypted_payload = encrypt(json.dumps(payload), REP_PUB_KEY)
    signed_payload_ = signed_payload(encrypted_payload, private_key)
    with open(session_file_name, "w") as session_file:
        session_data["seq_number"] += 1
        json.dump(session_data, session_file, indent=4)

    try:
        response = requests.post(API_ENDPOINT, json=signed_payload_)
        payload = unpack_signed_payload(response.json(), REP_PUB_KEY)
        if response.status_code == 200:
            try:
                print("Response:", decrypt(payload, private_key))
            except KeyError as e:
                sys.exit(1)
        else:
            print("Response:", payload)
            sys.exit(-1)

    except requests.RequestException as e:
        print(f"An error occurred: {e}")






if __name__ == "__main__":
    state = load_state()
    state = parse_env(state)

    parser = argparse.ArgumentParser(description="Console application with subcommands for each API function.")
    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    list_parser = subparsers.add_parser('list_orgs', help="List organizations")
    list_parser.set_defaults(func=lambda args: rep_list_orgs(state))

    creds_parser = subparsers.add_parser('rep_subject_credentials', help="Generate subject credentials")
    creds_parser.add_argument('--password', required=True, help="Password for encrypting credentials")
    creds_parser.add_argument('--output', required=True, help="Path to save the encrypted private key")
    creds_parser.set_defaults(func=lambda args: rep_subject_credentials(args.password, args.output))

    args = parser.parse_args()
    if args.command:
        args.func(args)
    else:
        parser.print_help()

    save(state)
