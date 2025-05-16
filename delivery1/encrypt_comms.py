from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7
import base64
import os
import json

def encode_binary_data(payload):
    encoded_payload = {}
    for key, value in payload.items():
        if isinstance(value, bytes):  # If binary, encode it
            encoded_payload[key] = base64.b64encode(value).decode('utf-8')
        else:  # Leave other data as-is
            encoded_payload[key] = value
    return encoded_payload


def decode_binary_data(encoded_payload):
    decoded_payload = {}
    for key, value in encoded_payload.items():
        if isinstance(value, str):  # Check if the value is a string (potentially base64-encoded)
            try:
                # Try to decode; if it fails, it's not valid base64
                decoded_payload[key] = base64.b64decode(value)
            except (ValueError, base64.binascii.Error):
                # If decoding fails, keep the value as-is
                decoded_payload[key] = value
        else:  # Leave other data as-is
            decoded_payload[key] = value
    return decoded_payload


def encrypt(plaintext: str, pubkey: str):
    #Symmetric encryption
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()


    #Encrypt the symmetric key with the public key
    public_key = serialization.load_pem_public_key(pubkey.encode())

    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Encrypt the MAC key with the public key
    mac_key = os.urandom(32)
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(encrypted_key)
    signature = h.finalize()
    encrypted_mac_key = public_key.encrypt(
        mac_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_data = {
        "encrypted_payload": encrypted_text,
        "encrypted_key": encrypted_key,
        "iv": iv,
        "signature": signature,
        "encrypted_mac_key": encrypted_mac_key
    }

    
    return encode_binary_data(encrypted_data)

def decrypt(encrypted_data: dict, privkey: str):
    encrypted_data = decode_binary_data(encrypted_data)
    private_key = serialization.load_pem_private_key(privkey.encode(),password=None)
    #Decrypt the symmetric key
    key = private_key.decrypt(
        encrypted_data["encrypted_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Decrypt the MAC key
    mac_key = private_key.decrypt(
        encrypted_data["encrypted_mac_key"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Verify the MAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(encrypted_data["encrypted_key"])
    h.verify(encrypted_data["signature"])

    #Decrypt the payload
    cipher = Cipher(algorithms.AES(key), modes.CBC(encrypted_data["iv"]))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data["encrypted_payload"]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()
    
    
