from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64
import os


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
    # Symmetric encryption
    iv = os.urandom(16)
    public_key = serialization.load_pem_public_key(pubkey.encode())

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # Generate ephemeral EC private key
        ephemeral_private_key = ec.generate_private_key(public_key.curve)
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # Derive a longer key to split into encryption and MAC keys
            salt=None,
            info=b"ecdh-encryption"
        ).derive(shared_key)

        # Split the derived key into encryption key and MAC key
        key, mac_key = derived_key[:32], derived_key[32:]

        ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        encrypted_key = b""  # Placeholder since we're deriving the key directly
    else:
        # RSA encryption for symmetric key and MAC key
        key = os.urandom(32)
        mac_key = os.urandom(32)
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ephemeral_public_key = None

    # Encrypt the payload
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_data) + encryptor.finalize()

    # Compute MAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(encrypted_key if encrypted_key else key)  # Use encrypted_key or derived key
    signature = h.finalize()

    encrypted_data = {
        "encrypted_payload": encrypted_text,
        "encrypted_key": encrypted_key,
        "iv": iv,
        "signature": signature,
        "encrypted_mac_key": mac_key,  # Include mac_key for RSA, not needed for EC
    }

    if ephemeral_public_key:
        encrypted_data["ephemeral_public_key"] = ephemeral_public_key

    return encode_binary_data(encrypted_data)



def decrypt(encrypted_data: dict, privkey: str):
    encrypted_data = decode_binary_data(encrypted_data)
    private_key = serialization.load_pem_private_key(privkey.encode(), password=None)

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        # Derive the shared key using ephemeral public key
        ephemeral_public_key = serialization.load_pem_public_key(
            encrypted_data["ephemeral_public_key"]
        )
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # Same as in encryption
            salt=None,
            info=b"ecdh-encryption"
        ).derive(shared_key)

        # Split the derived key into encryption key and MAC key
        key, mac_key = derived_key[:32], derived_key[32:]
    else:
        # RSA decryption for symmetric key and MAC key
        key = private_key.decrypt(
            encrypted_data["encrypted_key"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        mac_key = encrypted_data["encrypted_mac_key"]

    # Verify the MAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(encrypted_data["encrypted_key"] if encrypted_data["encrypted_key"] else key)
    h.verify(encrypted_data["signature"])

    # Decrypt the payload
    cipher = Cipher(algorithms.AES(key), modes.CBC(encrypted_data["iv"]))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data["encrypted_payload"]) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

