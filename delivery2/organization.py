from enum import Enum

class Organization:
    class OrganizationPermissions(Enum):
        ROLE_ACL = 0        # Modify the ACL
        SUBJECT_NEW = 1     # Add a new subject
        SUBJECT_DOWN = 2    # Suspend a subject
        SUBJECT_UP = 3      # Reactivate a subject
        DOC_NEW = 4         # Add a new document

    def __init__(self, acl):
        self.acl = acl
        self.document_list = []

    def __repr__(self):
        return {
            "acl": self.acl,
            "document_list": self.document_list
        }
