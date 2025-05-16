# Participants:

| Nome            |  NMec  |
| :-------------- | :----: |
| Afonso Ferreira | 113480 |
| Tomás Brás      | 112665 |
| Ricardo Antunes | 115243 |

# Features implemented with Commands

We created a set of database tables to manage a system involving subjects, organizations, roles, permissions, documents, and files.

Our repository has a master key associated with it, whose password is <strong>art</strong>

<strong>The commands do not work because we do not have these elements in the database. They are only intended to show how they can be introduced.</strong>

## Local Commands

Generates public and private keys

- `rep_subject_credentials <password> <credentials_file>`

- `./rep_subject_credentials "banana" "credentials/credential.pem"`

Decrypts a file

- `./rep_decrypt_file <encrypted_file> <metadata>`

## Anonymous API

Create Organization

- `./rep_create_org <organization> <username> <name> <email> <public key file>`

- `./rep_create_org "MyOrg1" "user1" "User One" "user1@example.com" "credentials/credential_public.pem"`

List Organizations

- `./rep_list_orgs`


Create Session

- `rep_create_session <organization> <username> <password> <credentials file> <session file>`

- `./rep_create_session "MyOrg1" "user2" "banana2" "credentials/credential2.pem" "session/sessionFile2.json"
`

Download file

- `./rep_get_file <file_handle> <password> <output_file>`

- `./rep_get_file "doc1" "jorge.txt"`

## Authenticated API

List subjects (of my organization)

- `rep_list_subjects <session file> [username] `
- 

List documents (with filtering options, such as dates or creators).

- `./rep_list_docs <session file>`
- 


## Authorized API

Add subject

- `rep_add_subject <session file> <username> <name> <email> <credentials file>`

- `./rep_add_subject "session/sessionFile.json" "user2" "utilizador2" "user2@gmail.com" "credentials/credential2_public.pem"
`

Change subject status- (suspend/reactivate)

- `rep_suspend_subject <session file> <username> `
- ``
- `rep_activate_subject <session file> <username>`
- ``

Upload a document

- ` rep_add_doc <session file> <document name> <file>`
- ` ./rep_add_doc "session/sessionFile.json" "doc1" "jorge.txt"
`

Download a document metadata

- `rep_get_doc_metadata <session file> <document name>`
- `./rep_get_doc_metadata "session/sessionFile.json" "doc1"
`


Get the plain text of a document

- `rep_get_doc_file <session file> <document name> [file]`
- `./rep_get_doc_file "session/sessionFile.json" "doc1" "jorge.txt"`

Delete a document

- `./rep_delete_doc session1 doc1`
- `./rep_delete_doc "session/sessionFile.json" "doc1"`


## Encrypt and decrypt file

### Encrypt file

```
./rep_add_doc session1 doc1
```

The encryption process in the /document/create endpoint ensures the secure storage of file content by utilizing AES-GCM (Advanced Encryption Standard - Galois/Counter Mode), a modern encryption method providing both confidentiality and integrity. Below is an overview of the steps involved:

- Key and Parameter Generation:
  A 256-bit encryption key is randomly generated using os.urandom(32).
  A 96-bit nonce (unique for each encryption) is generated usingos.urandom(12).
  A 128-bit salt is generated using os.urandom(16) for potentialuse in key derivation.

- File Padding:
  The file content is padded using PKCS7 to align its size withthe AES block size (16 bytes). This ensures compatibility withthe encryption process.

- AES-GCM Encryption:
  The padded content is encrypted using AES-GCM, which provides:
  Ciphertext: The encrypted file content.
  Authentication Tag: A cryptographic tag ensuring theintegrity and authenticity of the data.
  The encryption uses the generated key, nonce, and paddedcontent as inputs.

- Metadata Creation:
  A metadata string (alg) is generated in the following format:

  ```
  SHA256|AES-GCM|<salt>|<nonce>|<tag>
  ```

  This metadata contains all necessary parameters (excluding thekey) for decrypting the file later.

- File Handle:
  A unique identifier for the encrypted file (f_handle) isgenerated using the SHA-256 hash of the encrypted content.

- Database Storage:
  The encrypted content, metadata, and key are stored in the database:
  - File Table: Stores the encrypted content (content)- metadata (alg), and encryption key (key).
  - Document Table: Links the document to the file and record- additional details like its name and creation date.

This encryption process ensures secure, unique encryption for each file while maintaining the ability to verify the integrity and authenticity of the data during decryption.

### Decrypt file

```
./rep_decrypt_file teste.txt {
    "alg": "SHA256|AES-GCM|326ed9f396ea36ca3c0abb847fef2bb1|6687b3cc39da8204a8feaa1d|78d38d601325caab70b11b73e0cc416f",
    "password": "ac619cab96b2191c1c72036ca112c6655146a60f543772672759df50e7b675d9"
}
```

The decryption process reverses the encryption using the metadata and password:

- Loading Metadata: The metadata is read from a .json file. The metadata contains details like the salt, nonce, and authentication tag, which are extracted from the alg fieldKey

- Verify Integrity: Before decrypting the file, we read the cipher text from the file and digest it using SHA-256 to obtain the 'file handle'. We then compare the new file handle with the one stored in the database to ensure the file has not been tampered with.

- Derivation: The same password-based key derivation process is used as in encryption: The password and salt from the metadata generate the encryption key

- AES-GCM Decryption:The encrypted file content (ciphertext) is read. The AES-GCM decryption uses the derived encryption key, the nonce, ciphertext, and authentication tag from the metadata.

- If the decryption succeeds: The original plaintext is returned.


### Protection against attacks

- Protection against eavesdropping: we encrypted the messages from the client and from the server when the authenticated API is used and a result is returned (not error), by using hybrid encryption on the payload (body content). This way, even if an attacker can look into the packets sent, they cannot discern what was sent

- Protection against manipulation: in the previously mentioned protection, we used a symmetric key to encrypt the payload and another key to generate a MAC which we then encrypted (alongside the symmetric key) by using the repository / session's public key. We used the MAC to digest the encrypted payload, therefore we can check if the content was tampered with without even needing to decrypt the content itself

- Protection against replay: we have a nonce and a sequential number in every message sent by a session, which we use to protect ourselves from hijacking and replay attacks. The nonce protects against replay attacks, as once a nonce is used, it cannot be used again by the same session, therefore if the same packet were to be sent to the repository, a transgression would be detected. The sequential number protects against hijacking attacks by not allowing messages with a sequential number lower than the current one saved in the repository, therefore if an attacker hijacks a packet and saves it to send it later, they won't be successful due to this measure (as long as other packets were sent in-between)
