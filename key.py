import codecs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import subprocess

def gen_wg_keys_os():
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo '{privkey}' | wg pubkey", shell=True).decode("utf-8").strip()

    return privkey, pubkey

def gen_wg_keys():
    # generate private key
    private_key = X25519PrivateKey.generate()

    bytes_ = private_key.private_bytes(  
        encoding=serialization.Encoding.Raw,  
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
     
    # derive public key
    pubkey = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    sk = codecs.encode(bytes_, 'base64').decode('utf8').strip()
    pk = codecs.encode(pubkey, 'base64').decode('utf8').strip()

    return sk, pk

