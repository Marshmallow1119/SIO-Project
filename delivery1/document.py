from enum import Enum
class Document:
    class DocumentPermissions(Enum):
        DOC_ACL = 0     # Modify the Access Control List
        DOC_READ = 1    # Read the file content
        DOC_DELETE = 2  # Delete the associated file content

    def __init__(self, document_handle, name, create_date, creator, file_handle, encrypted_key, acl=None, alg=None):

        # Public metadata
        self.document_handle = document_handle
        self.name = name
        self.create_date = create_date
        self.creator = creator
        self.file_handle = file_handle
        self.acl = acl if acl else {}
        self.deleter = None

        # Private metadata
        self.alg = alg
        self.encrypted_key = encrypted_key

    def __repr__(self):
        return {
            "doc_handle": self.document_handle,
            "name": self.name, 
            "create_date": self.create_date, 
            "creator": self.creator, 
            "file_handle": self.file_handle, 
            "acl": self.acl, 
            "deleter": self.deleter
            }

