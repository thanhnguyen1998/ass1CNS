from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as rsa
from Crypto import Random
import file_manager as file

def generate_key(folderToSave_key):
    key = RSA.generate(2048)
    file.check_and_create_folder(folderToSave_key)
    with open(folderToSave_key + "\public_key.pem","wb") as public:
        with open(folderToSave_key + "\private_key.pem","wb") as private:
            public.write(key.publickey().exportKey())
            private.write(key.exportKey())
            public.close()
            private.close()

def encrypt_rsa(plaintext, filepath_key):
    publickey = RSA.importKey(open(filepath_key).read())
    cipher = rsa.new(publickey)
    return cipher.encrypt(plaintext)

def decrypt_rsa(ciphertext,filepath_key):
    privatekey = RSA.importKey(open(filepath_key).read())
    sentinel = Random.new().read(20)
    cipher = rsa.new(privatekey)
    return cipher.decrypt(ciphertext,sentinel)