import pathlib
import logging
from sys import stderr
from getpass import getpass
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import bcrypt, PBKDF2, scrypt
from Crypto.PublicKey import RSA


logger = logging.getLogger(__name__)
logger.setLevel("INFO")
logger.addHandler(logging.StreamHandler(stderr))


class NotRandRSA:
    def __init__(self, master):
        self.master = master
        self.i = 0
        return

    def notrand(self, n):
        self.i += 1
        return PBKDF2(self.master, str(self.i), dkLen=n, count=1)


# if __name__ == "__main__":
#     print('generating...')
#     print(key.export_key(format="PEM"))
#     print(key.public_key().export_key(format="OpenSSH"))




def derive_key(password, salt):
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)


def encrypt_symmetric(plaintext, key):
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)

    cipher = AES.new(key, AES.MODE_CCM, nonce)  # read more https://en.wikipedia.org/wiki/CCM_mode
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return salt + nonce + tag + ciphertext


def derive_symmetric_key(base: bytes = None, salt: bytes = None):
    base = base or get_random_bytes(256)
    salt = base or get_random_bytes(16)
    key = PBKDF2(base, salt, dkLen=32, count=10)
    return key


def decrypt_symmetric(encrypted_data, key):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]

    cipher = AES.new(key, AES.MODE_CCM, iv)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(e)
        raise ValueError("Decryption failed, data may be tampered with!")

    return plaintext


def encrypt_file_symmetric(file: pathlib.Path, key: bytes):
    content = file.read_bytes()
    encrypt_symmetric(content, key)


if __name__ == "__main__":
    # Generate pseudorandom ECC key

    password = getpass()
    master_key = bcrypt(password, 12, b'a'*16)
    notrand = NotRandRSA(master_key)
    logger.info("generating RSA")
    asym_kek = RSA.generate(4096, randfunc=notrand.notrand)

    # Generation symmetric key
    # TODO: Update with user options
    symmetric_key_derivation_base = None
    symmetric_key_derivation_salt = None
    logger.info("deriving symmetric key")
    symmetric_key = derive_symmetric_key(symmetric_key_derivation_base, symmetric_key_derivation_salt)

    # Read target file
    with open("test.txt", 'rb') as target_file:
        content = target_file.read()

    # Encrypt target file contents using symmetric key
    logger.info("encrypting plaintext")
    cipher_text = encrypt_symmetric(content, symmetric_key)

    # Encrypt symmetric key using asymmetric key
    logger.info("encryping symmetric key")
    asymm_kek_pub = asym_kek.public_key()
    rsa_cipher = PKCS1_OAEP.new(asymm_kek_pub)
    encrypted_symmetric_key = rsa_cipher.encrypt(symmetric_key)
    print(encrypted_symmetric_key)
    print(asym_kek.export_key().decode())

    rsa_cipher = PKCS1_OAEP.new(asym_kek)
    decrypted_symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)

    result = decrypt_symmetric(cipher_text, decrypted_symmetric_key)

    print(result)

