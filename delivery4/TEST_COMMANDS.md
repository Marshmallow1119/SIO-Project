### Para criar/reset na base de dados é apenas necessário correr:

```bash
python3 reset.py
```

### Inicializar o repositorio:

```bash
python3 repository.py
```

#### Password: art

### Criar credenciais para um subject:

```bash
./rep_subject_credentials "banana" "credentials/credential.pem"
```

- Gera um ficheiro com as chave publica e privada do subject com a chave privada encriptada com a password "banana"

### Criar organização:

```bash
./rep_create_org "MyOrg1" "user1" "User One" "user1@example.com" "credentials/credential.pem"
```

- Cria uma organização com o nome "MyOrg1" e cria o role "Manager" que tem todas as permissões para o user "user1" com o nome "User One"

### Listar organizações:

```bash
./rep_list_orgs
```

### Criar uma sessão:

```bash
./rep_create_session "MyOrg1" "user1" "banana" "credentials/credential.pem" "session/sessionFile.json"
```

- Cria uma sessão para para o user "user1" na organização realizando o processo de autenticação. A sessão é guardada no ficheiro "session/sessionFile.json"

#### Exemplo de um ficheiro de sessão:

```json
{
  "REP_PUB_KEY": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy4IR2VUInvca1YR/Sj+z\nN9dYTFbdDmY0F2Srn1YcWiPlv6RsgZBFa8WYFBhW4Xl/cKkpIq+t9MBS6D5aHCRL\nkCANm50gQ4dW3Qf6CAsNmhF4gkeqsHsFgChWQL3Prf4xquE8go2l0v6Ex2w0UKRE\niFsdfFKsKlLQo6x/6GbvR2o74O74A0CTcFtXy9wWJLfbj+csH3bQjdnvH52biwZt\np4qS0QftVn3a1z2IbnXJ3kXG8sgdtY/yeOd9xX9DHAMwH+jbS92yiGSpMlQWRSGe\nN7gAW9oyGTmX/jY0CIswatfRbLsXAaSld/MWZJfTzZ7wrYizlFNLpaOxmA338FID\ngwIDAQAB\n-----END PUBLIC KEY-----",
  "organization_id": 1,
  "signature": "261825237f97db68f8c16f7d3a80c9ef2bd0520bafe675ce1219a7f0daa2894daa6facba0e557cc3725568130604b44bd0dbe4d95bbbb5bdee8ab357d8d986bc0052b02d9e1672191d95ec00115d408ba6a50d02eb81609d98c6fdb695f2d630ee5227dd1c286061c3c71161338c2b4b5725568765410289d4a9a0b00178ed625ea115d609525ca58a96d3de8ecb5a1f0c04e86cc04cf8ca2676717a438ec6e102b4e0e2073e18643822f93c7e45635d55fd3447e7b70e19646d460bc56d7674e24e979ad8f7371c851bcbb9263ccaef71bc194956d34089d547b3de9920fd3d682a29413ffa2b46ee160364ddef69fa1240f291139374adc82716947a146190",
  "subject_id": 1,
  "PRIV_KEY": "user1_MyOrg1.pem",
  "seq_number": 0
}
```

### Assumir o role de 'Manager':

```bash
 ./rep_assume_role "session/sessionFile.json" "Manager"
```

### Criar novas credenciais para um subject:

```bash
./rep_subject_credentials "banana2" "credentials/credential2.pem"
```

### Adicionar um novo subject à organização:

```bash
./rep_add_subject "session/sessionFile.json" "user2" "utilizador2" "user2@gmail.com" "credentials/credential2.pem"
```

### Adicionar um novo role à organização:

```bash
./rep_add_role "session/sessionFile.json" "newrole"
```

### Adicionar permissões a um role:

```bash
./rep_add_permission "session/sessionFile.json" "newrole" "SUBJECT_NEW"
```

### Remover permissões a um role:

```bash
./rep_remove_permission "session/sessionFile.json" "newrole" "SUBJECT_NEW"
```

### Adicionar um role a um subject:

```bash
./rep_add_permission "session/sessionFile.json" "newrole" "user2"
```

### Remover um role a um subject:

```bash
./rep_remove_permission "session/sessionFile.json" "newrole" "user2"
```

### Listar as permissoes de um role:

```bash
./rep_list_role_permissions "session/sessionFile.json" "Manager"
./rep_list_role_permissions "session/sessionFile.json" "newrole"
```

#### Exemplo de output:

```bash
Response: {"role_permissions": {"org": ["ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"], "docs": {}}}
```

### Listar roles da sessão:

```bash
./rep_list_roles "session/sessionFile.json"
```

### Listar todos os roles que um determinado subject pode assumir:

```bash
./rep_list_subject_roles "session/sessionFile.json" "user1"
```

### Listar todos os roles que têm uma determinado permissão na organização da sessão atual:

```bash
./rep_list_permission_roles "session/sessionFile.json" "DOC_NEW"
```

### Adicionar um documento à organização:

```bash
./rep_add_doc "session/sessionFile.json" "doc1" "jorge.txt"
```

### Obter a metadata de um documento:

```bash
./rep_get_doc_metadata "session/sessionFile.json" "doc1"
```

#### Exemplo de output:

```json
{
  "document_name": "doc1",
  "creation_date": "2025-01-26",
  "creator": 1,
  "organization_id": 1,
  "cipher_text": "crFV/3dbcFuzwbao45X3KEJXBJCeRC7RVQI=",
  "file_handle": "281b9ebde5f852f23c679e6cc37c64407ba36e6381e871b0c9191d28f3b226cd",
  "password": "d5833f9a0aa738e4fb2b2aaeab4faea602d83a483c7f91bfaee1d93534115f91",
  "encryption_details": {
    "algorithm": "AES-GCM",
    "salt": "304a3252bbe398b9147a6f40cdc4734c",
    "nonce": "e9c25335004fe3cd08a68174",
    "tag": "847f9fe4831488a16799092e2abd3144"
  }
}
```

### Obter um ficheiro encriptado:

```bash
./rep_get_file 281b9ebde5f852f23c679e6cc37c64407ba36e6381e871b0c9191d28f3b226cd "download.txt"
```

### Desencriptar um ficheiro:

```bash
./rep_decrypt_file "download.txt" metadata.json
```

### Transferir um documento desencriptado:

```bash
./rep_get_doc_file "session/sessionFile.json" "doc1" "testeOutput.txt"
./rep_get_doc_file "session/sessionFile.json" "doc1"
```

### Listar documentos da organização:

```bash
./rep_list_docs "session/sessionFile.json"
./rep_list_docs "session/sessionFile.json" -s "user1"
./rep_list_docs "session/sessionFile.json" -d nt 20-01-2025
./rep_list_docs "session/sessionFile.json" -d ot 20-02-2025
```

### Adicionar/remover permissões de um documento:

```bash
./rep_acl_doc "session/sessionFile.json" "doc1" "+" "newrole" "DOC_READ"
./rep_acl_doc "session/sessionFile.json" "doc1" "-" "newrole" "DOC_READ"
./rep_acl_doc "session/sessionFile.json" "doc1" "newrole" "DOC_READ"
```

### Suspender um subject:

```bash
./rep_suspend_subject "session/sessionFile.json" "user2"
```

### Ativar um subject:

```bash
./rep_activate_subject "session/sessionFile.json" "user2"
```

### Reativar um role:

```bash
./rep_suspend_role "session/sessionFile.json" "newrole"
```

### Ativar um role:

```bash
./rep_reactivate_role "session/sessionFile.json" "newrole"
```
