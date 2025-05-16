import sys
import os
import client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding



def decrypt_file(file_name, privkey_file, decrypted_file, password):
    try:
        if not os.path.exists(file_name):
            print(f"Erro: O arquivo '{file_name}' não existe.")
            return

        if not os.path.exists(privkey_file):
            print(f"Erro: O arquivo de chave privada '{privkey_file}' não existe.")
            return

        with open(file_name, 'rb') as data_file:
            ciphertext = data_file.read()

        with open(privkey_file, 'rb') as key_file:
            try:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode(),
                )
            except ValueError:
                print("Erro: Senha incorreta para a chave privada.")
                return
            except Exception as e:
                print(f"Erro ao carregar a chave privada: {e}")
                return

        key_size = private_key.key_size // 8
        decrypted_text = b''

        for i in range(0, len(ciphertext), key_size):
            block = ciphertext[i:i + key_size]
            try:
                decrypted_block = private_key.decrypt(
                    block,
                    padding.PKCS1v15()
                )
                decrypted_text += decrypted_block
            except Exception as e:
                print(f"Erro ao descriptografar o bloco {i // key_size}: {e}")
                return

        with open(decrypted_file, 'wb') as dec_file:
            dec_file.write(decrypted_text)

        print(f"Arquivo descriptografado com sucesso: '{decrypted_file}'")

    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python decrypt_file.py <arquivo_criptografado> <chave_privada> <senha>")
    else:
        decrypt_file(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
