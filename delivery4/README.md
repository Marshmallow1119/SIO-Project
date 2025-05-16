# Delivery 4 - CHANGE-LOG - IMPROVEMENTS AND CHANGES

## Mudanças gerais:

- Criação de um ficheiro 'reset.py' que apaga a base de dados atual e cria uma nova usando as tabelas de 'schema.sql'
- Criação de um script 'run_tests.sh' que contém todos os comandos que podem ser aplicados e faz uma pequena demonstração dos mesmos. Existem alguns comandos que darão erro para propósitos de demonstração de verificação, por exemplo tentar tirar permissões a um manager.
- Criação de um ficheiro 'TEST_COMMANDS.md' que contém os comandos usados para testar o sistema, sendo que alguns destes comandos têm uma breve explicação do que fazem/output.
- Organização do repositório

## Mudanças no código:

- Atualização do comando 'rep_get_doc_metadata'. Este agora faz print da metadata do documento e guarda no ficheiro metadata.json. Isto ajuda depois no uso do comando 'rep_decrypt_file' podendo usar este ficheiro sem ter que alterar nada e assim obter o ficheiro desencriptado.
- Agora ao adicionar um documento, o file_handle do mesmo é calculado através do hash do plain text e não do cipher text. Isto permite-nos garantir integridade do documento quando o estamos a desencriptar.
- Quando uma sessão é criada (rep_create_session), o challenge não é encriptado. O cliente recebe esse challenge e retorna apenas a sua assinatura, sem encriptação. No repositório, o challenge também não é encriptado. Em vez de comparar diretamente o challenge recebido com o armazenado, o repositorio verifica se a assinatura fornecida pelo cliente é válida.
- Os roles agora não são case-sensitive, corrigindo o problema de não ser possível listar o as permissões/roles do "Manager"
- As par de chaves criadas com rep_subject_credentials que antes eram dois ficheiros separados (credential.pem e credential_public.pem) agora são um só ficheiro (credential.pem). A chave privada é encriptada com a password fornecida pelo utilizador.
- Adicionámos logging no repositorio. O repositorio para além de fazer print das mensagens, guarda-as num ficheiro 'repository.log' todos os eventos que ocorrem no repositorio.

## Mudanças no relatório:

- Reorganização do relatório
- Atualização do capítulo da 'Authentication' explicando melhor como foi feita e as decisões tomadas.
- Adição de um novo capítulo "Roles"
- Adição de um novo capítulo "Subjects"
- Adição de um novo capítulo "ACL" onde se fala sobre a ACL da Organização e da ACL dos documentos
- Alteração do texto de algumas partes do relatório, nomeadamente os tópicos sobre encriptação e desencriptação de documentos e a descrição do comando 'rep_get_doc_metadata'.

O relatório está no ficheiro **'report.pdf'**

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

#### Generates public and private keys

- `rep_subject_credentials <password> <credentials_file>`
- Example: `./rep_subject_credentials "banana" "credentials/credential.pem"`

#### Decrypts a file

- `./rep_decrypt_file <encrypted_file> <metadata>`
- Example: `./rep_decrypt_file jorgeEncr.txt metadata.json`

## Anonymous API

#### Create Organization

- `rep_create_org <organization> <username> <name> <email> <public key file>`
- Example: `./rep_create_org "MyOrg1" "user1" "User One" "user1@example.com" "credentials/credential_public.pem"`

#### List Organizations

- Example: `./rep_list_orgs`

#### Create Session

- `rep_create_session <organization> <username> <password> <credentials file> <session file>`
- Example: `./rep_create_session "MyOrg1" "user1" "banana1" "credentials/credential1.pem" "session/sessionFile.json"`

#### Download file

- `rep_get_file <file_handle> <password> <output_file>`
- Example: `./rep_get_file "doc1" "jorge.txt"`

## Authenticated API

#### List subjects (of my organization)

- `rep_list_subjects <session file> [username] `
- Example: `./rep_list_subjects session/sessionFile.json`
- Example: `./rep_list_subjects session/sessionFile.json user2`

#### List documents (with filtering options, such as dates or creators).

- `rep_list_docs <session file> [-s username] [-d nt/ot/et date]`
- Example: `./rep_list_docs session/sessionFile.json -d nt 11-10-2024`
- Example: `./rep_list_docs "session/sessionFile.json"`
- Example: `./rep_list_docs session/sessionFile.json -s user1`

### Second Delivery commands

#### Request the given role for the session

- `rep_assume_role <session file> <role>`
- `./rep_assume_role "session/sessionFile.json" "manager"`

#### Release the role for the session

- `rep_drop_role <session file> <role>`
- Examp`./rep_drop_role "session/sessionFile2.json" "newrole"`

#### List the current session roles

- `rep_list_roles <session file> <role>`
- Example: `./rep_list_roles "session/sessionFile.json" `

#### List the subjects of the organization with which I have currently a session.

- `rep_list_subjects <session file> [username]`
- `./rep_list_subjects "session/sessionFile.json" "user1"`

#### List the subjects of a role of the organization with which I have currently a session.

- `rep_list_role_subjects <session file> <role>`
- `./rep_list_role_subjects "session/sessionFile.json" "manager"`

#### List the roles of a subject of the organization with which I have currently a session.

- `rep_list_subject_roles <session file> <username>`
- Example: `./rep_list_subject_roles "session/sessionFile.json" "user1"`

#### List the permissions of a role of the organization with which I have currently a session.

- `rep_list_role_permissions <session file> <role>`
- Example: `./rep_list_role_permissions "session/sessionFile.json" "manager"`

#### List the roles of the organization with which I have currently a session that have a given permission

- `rep_list_permission_roles <session file> <permission>`
- Example: `./rep_list_permission_roles "session/sessionFile.json" "DOC_READ"`

## Authorized API

#### Add subject

- `rep_add_subject <session file> <username> <name> <email> <credentials file>`
- Example: `./rep_add_subject "session/sessionFile.json" "user2" "utilizador2" "user2@gmail.com" "credentials/credential2_public.pem"
`

#### Change subject status - (suspend/reactivate)

- `rep_suspend_subject <session file> <username> `
- Example: `./rep_suspend_subject "session/sessionFile1.json" "user1"`

<br>

- `rep_activate_subject <session file> <username>`
- Example: `./rep_activate_subject "session/sessionFile1.json" "user1"`

#### Upload a document

- `rep_add_doc <session file> <document name> <file>`
- Example: `./rep_add_doc "session/sessionFile.json" "doc1" "jorge.txt"`

#### Download a document metadata

- `rep_get_doc_metadata <session file> <document name>`
- Example: `./rep_get_doc_metadata "session/sessionFile.json" "doc1"`

#### Get the plain text of a document

- `rep_get_doc_file <session file> <document name> [file]`
- Example: `./rep_get_doc_file "session/sessionFile.json" "doc1" "jorge.txt"`

#### Delete a document

- `rep_delete_doc session1 doc1`
- Example: `./rep_delete_doc "session/sessionFile.json" "doc1"`

### Second Delivery commands

#### Add a role to the organization with which I have currently a session

- `rep_add_role <session file> <role>`
- Example: `./rep_add_role "session/sessionFile.json" "newrole"`

#### Change role status - (suspend/reactivate)

- `rep_suspend_role <session file> <role>`
- Example: `./rep_suspend_role "session/sessionFile.json" "newrole"`

<br>

- `rep_reactivate_role <session file> <role>`
- Example: `./rep_reactivate_role "session/sessionFile.json" "newrole"`

#### Change the properties of a role in the organization with which I have currently a session

- `rep_add_permission <session file> <role> <username>`
- Example: `./rep_add_permission "session/sessionFile.json" "newrole" "user2"`

<br>

- `rep_remove_permission <session file> <role> <username>`
- Example: `./rep_remove_permission "session/sessionFile.json" "newrole" user2`

<br>

- `rep_add_permission <session file> <role> <permission>`
- Example: `./rep_add_permission "session/sessionFile.json" "newrole" "SUBJECT_NEW"`

<br>

- `rep_remove_permission <session file> <role> <permission>`
- Example: `./rep_remove_permission "session/sessionFile.json" "newrole" "SUBJECT_NEW"`

#### Changes the ACL of a document (Add/Remove)

- `rep_acl_doc <session file> <document name> [+/-] <role> <permission>`
- Example: `./rep_acl_doc "session/sessionFile.json" "doc1" "+" "manager" "DOC_READ"`
- Example: `./rep_acl_doc "session/sessionFile.json" "doc1" "-" "manager" "DOC_READ"`
- Example: `./rep_acl_doc "session/sessionFile.json" "doc1" "manager" "DOC_READ"`

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
  A unique identifier for the encrypted file (f_handle) isgenerated using the SHA-256 hash of the **plain text** ~~~cipher text~~~. This hash is used to verify the integrity of the file content during decryption.

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

- Verify Integrity: Since the file handle is created using an hash of the plain text, after decrypting the content we can verify if the content has been tampered or not by **comparing the hash of the plain text with the file handle.**

- Derivation: The same password-based key derivation process is used as in encryption: The password and salt from the metadata generate the encryption key

- AES-GCM Decryption:The encrypted file content (ciphertext) is read. The AES-GCM decryption uses the derived encryption key, the nonce, ciphertext, and authentication tag from the metadata.

- If the decryption succeeds: The original plaintext is returned.

### Protection against attacks

- Protection against eavesdropping: we encrypted the messages from the client and from the server when the authenticated API is used and a result is returned (not error), by using hybrid encryption on the payload (body content). This way, even if an attacker can look into the packets sent, they cannot discern what was sent

- Protection against manipulation: in the previously mentioned protection, we used a symmetric key to encrypt the payload and another key to generate a MAC which we then encrypted (alongside the symmetric key) by using the repository / session's public key. We used the MAC to digest the encrypted payload, therefore we can check if the content was tampered with without even needing to decrypt the content itself

- Protection against replay: we have a nonce and a sequential number in every message sent by a session, which we use to protect ourselves from hijacking and replay attacks. The nonce protects against replay attacks, as once a nonce is used, it cannot be used again by the same session, therefore if the same packet were to be sent to the repository, a transgression would be detected. The sequential number protects against hijacking attacks by not allowing messages with a sequential number lower than the current one saved in the repository, therefore if an attacker hijacks a packet and saves it to send it later, they won't be successful due to this measure (as long as other packets were sent in-between)

### Second Delivery

#### Roles

In this delivery, we introduced the concept of <b>Roles</b> in our system. A role is a set of permissions that can be assigned to a subject. A subject can have multiple roles, and a role can be assigned to multiple subjects. Roles can be used to manage permissions in a more organized way, as they group permissions together. Some of the commands we implemented in this delivery are related to roles, such as adding a role to the organization, listing the roles of a subject, listing the subjects of a role, listing the permissions of a role, etc...

<b>Some of the permissions that can be applied to Roles are:</b>

- SUBJECT_NEW - allows the subject to create new subjects
- SUBJECT_DOWN - allows the subject to delete subjects
- SUBJECT_UP - allows the subject to reactivate suspended subjects
- ROLE_ACL - allows the subject to modify the ACL of a organization
- ROLE_NEW - allows the subject to create new roles
- ROLE_DOWN - allows to suspend roles
- ROLE_UP - allows to reactivate suspended roles
- ROLE_MOD - updates a role, allowing a role to add/remove a subject to/from an existing role or add/remove a permission to/from an existing role.
- DOC_NEW - allows the subject to create new documents

Besides the organization perms (which are the permissions that can be applied to the organization itself), we also have the document perms (which are the permissions that can be applied to documents). These document permissions are specific to each document.

<b>The document permissions are: </b>

- DOC_READ
- DOC_DELETE
- DOC_ACL

#### Authentication

- In this second iteration, we require the user to have a signature in their session file, used to authenticate the user without needing to use a password. The user obtains this signature by completing a challenge sent by the repository. The user needs to send a challenge request to the repository, which returns the solution of the challenge ~~encrypted by the subject's public key~~ relative to the subject the user wants to sign in as. The user will then ~~decrypt~~ **sign** the challenge, send the ~~solution~~ **signature** to the repository, and if the ~~solution~~ **signature** is valid, the repository will then create the session and give the user **its auth key's** signature, which authenticates the session file.

- Every time a request is made to the repository with the authenticated API, this request is signed using the session's private key. Upon arriving at the repository, several checks are made, the nonce check, the sequence_number check, the signature in the session file check and additionally the signature from the client is also checked against the subject's public key **(this is explained in detail in the report)**. This authenticates the message as having come from the subject and not from someone else. In case the content of the message is altered, the signature will no longer be valid, also protecting against manipulation.

#### Communication Confidentiality and Authenticity

- Every communication between the repository and the client is encrypted using the other receiver's PUBLIC KEY, guaranteeing protection and confidentiality in the communication, but it is also signed by using the sender's PRIVATE KEY, guaranteeing the authenticity of the message. This way, the client can act only if the response it receives is properly signed by the repository. Below is a visual representation of how the payload between each message is created (this is valid for the Authenticated API)

![image](https://github.com/user-attachments/assets/7c62c7ef-4be6-43a2-bdbe-65cc8de24a16)

- When sending the message, the peer encrypts the message, and then signs the resulting message. When receiving the message, the repository first needs to decrypt the message in order to verify the subject_id and organization_id, and then verifies the signature. Meanwhile the client can first check the signature before decrypting the message.

- For the Anonymous API, only half of this process is achieved - the client encrypts the body of the message it sends to ensure confidentiality, and the repository signs its own response, without encrypting it, as a means to ensure the message's authenticity. This ensures that even communications regarding the Anonymous API can be considered somewhat secure.
