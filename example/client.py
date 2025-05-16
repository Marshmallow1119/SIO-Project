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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

def rep_list_orgs():
    url = "http://127.0.0.1:5000/organization/list"  # Adjust if the Flask app is hosted elsewhere
    
    response = requests.get(url)
    
    if response.status_code == 200:
        organizations = response.json()
        print("Organizations:", json.dumps(organizations, indent=4))
    else:
        print("Error:", response.json())

def rep_subject_credentials(password, credentials_file):
    # Generate the ECC private key using the P-521 curve
    private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    
    # Derive a password-based encryption key
    password_bytes = password.encode()  # Convert password to bytes
    salt = os.urandom(16)  # Generate a random salt for KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encryption_key = kdf.derive(password_bytes)
    
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

def rep_subject_credentials(password, credentials_file):
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Derive encryption key from password
    password_bytes = password.encode()
    salt = os.urandom(16)  # Salt for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)
    
    # Encrypt the private key with the derived key
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )
    
    # Save the encrypted private key to the credentials file
    with open(credentials_file, 'wb') as priv_file:
        priv_file.write(encrypted_private_key)
    
    # Generate and save the public key
    public_key = private_key.public_key()
    public_key_file = credentials_file.replace(".pem", "_public.pem")
    
    with open(public_key_file, 'wb') as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    print("Keys generated successfully.")
    print(f"Private key saved to {credentials_file}")
    print(f"Public key saved to {public_key_file}")


state = load_state()
state = parse_env(state)
state = parse_args(state)

""" Do something """
req = requests.get(f"http://{state['REP_ADDRESS']}/organization/list")
print("---")
print(req.json())
print("---")
save(state)
