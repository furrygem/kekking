import pathlib
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import bcrypt, PBKDF2, scrypt
from Crypto.PublicKey import ECC


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


def encrypt(plaintext, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    nonce = get_random_bytes(12)

    cipher = AES.new(key, AES.MODE_CCM, nonce)  # read more https://en.wikipedia.org/wiki/CCM_mode
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return salt + nonce + tag + ciphertext


def decrypt(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]
    
    key = derive_key(password, salt)
    
    cipher = AES.new(key, AES.MODE_CCM, iv)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as e:
        print(e)
        raise ValueError("Decryption failed, data may be tampered with!")

    return plaintext


if __name__ == "__main__":
    password = getpass()
    master_key = bcrypt(password, 12, b'a'*16)
    notrand = NotRandRSA(master_key)
    asymm_key = ECC.generate(curve='p521', randfunc=notrand.notrand)
    plaintext = b'test'
    enc_data = encrypt(plaintext, password)
    print(enc_data)

    try:
        dec_data = decrypt(enc_data, password)
        print("Decrypted message:", dec_data.decode())
    except ValueError as e:
        print(str(e))
