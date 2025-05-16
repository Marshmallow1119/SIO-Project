import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

def read_file(file_path):
    with open(file_path, "rb") as file:
        return file.read()

file_handle = 1
file_path = "meu_arquivo.txt"
file_content = read_file(file_path)
alg = "AES"
key = "minha_chave_secreta"

cursor.execute(
    "INSERT INTO File (f_handle, content, alg, key) VALUES (?, ?, ?, ?)",
    (file_handle, file_content, alg, key)
)

conn.commit()
conn.close()

print("Arquivo inserido com sucesso!")
