CREATE TABLE Subject (
    id INTEGER PRIMARY KEY,
    fullname TEXT,
    email TEXT UNIQUE,
    username TEXT UNIQUE
);

CREATE TABLE Organization (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE
);

CREATE TABLE Subject_Org (
    subject_id INTEGER REFERENCES Subject(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES Organization(id) ON DELETE CASCADE,
    public_key TEXT,
    status_ TEXT DEFAULT 'active',
    PRIMARY KEY (subject_id, organization_id)
);

CREATE TABLE Subject_Role (
    subject_id INTEGER REFERENCES Subject_Org(subject_id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES Role(id) ON DELETE CASCADE,
    assumed BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (subject_id, role_id)
);

CREATE TABLE Session (
    id INTEGER PRIMARY KEY,
    last_interaction TIMESTAMP,
    keys TEXT,
    last_interaction_number INTEGER DEFAULT 0,
    subject_id INTEGER REFERENCES Subject(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES Organization(id) ON DELETE CASCADE
);

CREATE TABLE Nonce (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce TEXT,
    session_id INTEGER REFERENCES Session(id) ON DELETE CASCADE
);

CREATE TABLE Role (
    id INTEGER PRIMARY KEY,
    name TEXT,
    active BOOLEAN DEFAULT TRUE,
    organization_id INTEGER REFERENCES Organization(id) ON DELETE CASCADE
);

CREATE TABLE Perms (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE
);

CREATE TABLE Role_Perms (
    perm_id INTEGER REFERENCES Perms(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES Role(id) ON DELETE CASCADE,
    PRIMARY KEY (perm_id, role_id)
);

CREATE TABLE Document (
    d_handle INTEGER PRIMARY KEY,
    name TEXT,
    creation_date DATE,
    creator INTEGER REFERENCES Subject(id) ON DELETE SET NULL,
    organization_id INTEGER REFERENCES Organization(id) ON DELETE CASCADE,
    f_handle INTEGER REFERENCES File(f_handle) ON DELETE SET NULL
);

CREATE TABLE Challenge (
    id INTEGER PRIMARY KEY,
    challenge TEXT,
    subject_id INTEGER REFERENCES Session(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES Organization(id) ON DELETE CASCADE,
    timestamp TIMESTAMP NOT NULL
);


CREATE TABLE Role_Doc_Perms (
    perm_id INTEGER REFERENCES Perms(id) ON DELETE CASCADE,
    d_handle INTEGER REFERENCES Document(d_handle) ON DELETE CASCADE,
    role_id INTEGER REFERENCES Role(id) ON DELETE CASCADE,
    PRIMARY KEY (perm_id, d_handle, role_id)
);

-- Tabela File (armazena arquivos)
CREATE TABLE File (
    f_handle BYTEA PRIMARY KEY,
    content BYTEA,
    alg VARCHAR(50),
    key TEXT
);
