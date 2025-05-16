#!/bin/bash

# Reset database
python3 reset.py

# Create directory for credentials and session files if they don't exist
mkdir -p credentials
mkdir -p session

# Create credentials for a subject
./rep_subject_credentials "banana" "credentials/credential.pem"

echo "IMPORTANT: Repository has to be running"

# Create organization
./rep_create_org "MyOrg1" "user1" "User One" "user1@example.com" "credentials/credential.pem"

# List organizations
./rep_list_orgs

# Create a session
./rep_create_session "MyOrg1" "user1" "banana" "credentials/credential.pem" "session/sessionFile.json"

# Assume role of 'Manager'
./rep_assume_role "session/sessionFile.json" "Manager"

# Create new credentials for a subject
./rep_subject_credentials "banana2" "credentials/credential2.pem"

# Add a new subject to the organization
./rep_add_subject "session/sessionFile.json" "user2" "utilizador2" "user2@gmail.com" "credentials/credential2.pem"

# Create session for the new subject
./rep_create_session "MyOrg1" "user2" "banana2" "credentials/credential2.pem" "session/sessionFile2.json"

# Add a new role to the organization
./rep_add_role "session/sessionFile.json" "newrole"

# Add permissions to a role
./rep_add_permission "session/sessionFile.json" "newrole" "SUBJECT_NEW"

# Remove permissions from a role
./rep_remove_permission "session/sessionFile.json" "newrole" "SUBJECT_NEW"

# Assign a role to a subject
./rep_add_permission "session/sessionFile.json" "newrole" "user2"
./rep_assume_role "session/sessionFile2.json" "newrole"

# Remove a role from a subject
./rep_add_permission "session/sessionFile.json" "Manager" "user2"
./rep_remove_permission "session/sessionFile.json" "Manager" "user2"

# Add a document to the organization
./rep_add_doc "session/sessionFile.json" "doc1" "documento1.txt"

# List permissions of a role
./rep_list_role_permissions "session/sessionFile.json" "Manager"
./rep_list_role_permissions "session/sessionFile.json" "newrole"

# List roles of the session
./rep_list_roles "session/sessionFile.json"

# List all roles a subject can assume
./rep_list_subject_roles "session/sessionFile.json" "user1"

# List all roles with a specific permission
./rep_list_permission_roles "session/sessionFile.json" "DOC_NEW"

# Get metadata of a document
./rep_get_doc_metadata "session/sessionFile.json" "doc1"

# Get an encrypted file
./rep_get_file 28a70ea9d4486580a02e6342e790a0cd680b96ee78553ac7bae6143c1c9949c7 "encrypted_file.txt"

# Decrypt a file
./rep_decrypt_file "encrypted_file.txt" metadata.json

# Transfer a decrypted document
./rep_get_doc_file "session/sessionFile.json" "doc1" "testeOutput.txt"
./rep_get_doc_file "session/sessionFile.json" "doc1"

# List documents in the organization
./rep_list_docs "session/sessionFile.json"
./rep_list_docs "session/sessionFile.json" -s "user1"
./rep_list_docs "session/sessionFile.json" -d nt 20-01-2025
./rep_list_docs "session/sessionFile.json" -d ot 20-02-2025

# Try to read a document without permission
./rep_get_doc_file "session/sessionFile2.json" "doc1" 

# Manage document permissions
./rep_acl_doc "session/sessionFile.json" "doc1" "+" "newrole" "DOC_READ"
./rep_acl_doc "session/sessionFile.json" "doc1" "-" "newrole" "DOC_READ"
./rep_acl_doc "session/sessionFile.json" "doc1" "newrole" "DOC_READ"

# Try to read again but now with permission
./rep_get_doc_file "session/sessionFile2.json" "doc1"

# Suspend a subject
./rep_suspend_subject "session/sessionFile.json" "user2"

# Activate a subject
./rep_activate_subject "session/sessionFile.json" "user2"

# Suspend a role
./rep_suspend_role "session/sessionFile.json" "Manager"
./rep_suspend_role "session/sessionFile.json" "newrole"

# Reactivate a role
./rep_reactivate_role "session/sessionFile.json" "newrole"