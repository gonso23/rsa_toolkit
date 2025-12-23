#!/usr/bin/env python3
"""
RSA Encryption & Signing Toolkit - Asymmetric encryption + digital signatures
Keys stored as {name}_private_key.pem / {name}_public_key.pem in current directory
"""

import os
import sys
import argparse
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import base64
import struct

KEYS_DIR = "."  # Current directory

def generate_rsa_keypair(key_size=2048):
    """Generate RSA key pair"""
    print(f"Generating RSA-{key_size} key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    print("Key pair generated.")
    return private_key, public_key

def save_private_key(private_key, name):
    """Save private key with password protection"""
    password = getpass.getpass("Private key password: ").encode()
    password_confirm = getpass.getpass("Confirm password: ").encode()
    
    if password != password_confirm:
        print("Passwords do not match!")
        return False
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    
    filename = f"{name}_private_key.pem"
    with open(filename, 'wb') as f:
        f.write(pem)
    
    os.chmod(filename, 0o600)
    print(f"Private key saved: {filename}")
    return True

def save_public_key(public_key, name):
    """Save public key"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    filename = f"{name}_public_key.pem"
    with open(filename, 'wb') as f:
        f.write(pem)
    
    print(f"Public key saved: {filename}")
    return filename

def load_private_key(name):
    """Load private key"""
    filename = f"{name}_private_key.pem"
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return None
    
    password = getpass.getpass("Private key password: ").encode()
    
    try:
        with open(filename, 'rb') as f:
            pem = f.read()
        private_key = serialization.load_pem_private_key(
            pem, password=password, backend=default_backend()
        )
        return private_key
    except ValueError:
        print("Error: Invalid password")
        return None

def load_public_key(name):
    """Load public key"""
    filename = f"{name}_public_key.pem"
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return None
    
    with open(filename, 'rb') as f:
        pem = f.read()
    return serialization.load_pem_public_key(pem, backend=default_backend())

def encrypt_text_short(plaintext, public_key_name):
    """Encrypt short text with RSA - output to stdout with delimiters"""
    public_key = load_public_key(public_key_name)
    if public_key is None:
        return
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    encoded = base64.b64encode(ciphertext).decode('ascii')
    print("-------")
    print("crypt")
    print("-------")
    print(encoded)
    print("-------")

def encrypt_text_long(plaintext, public_key_name):
    """Encrypt long text with hybrid encryption - output like short text"""
    public_key = load_public_key(public_key_name)
    if public_key is None:
        return
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate AES key and IV
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len] * pad_len)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    
    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Pack everything: [aes_key_size][encrypted_aes_key][iv][ciphertext]
    packed = struct.pack('>I', len(encrypted_aes_key)) + encrypted_aes_key + iv + ciphertext
    encoded = base64.b64encode(packed).decode('ascii')
    
    print("-------")
    print("crypt")
    print("-------")
    print(encoded)
    print("-------")

def decrypt_text_short(encoded_text, private_key_name):
    """Decrypt short base64 text with RSA"""
    private_key = load_private_key(private_key_name)
    if private_key is None:
        return
    
    try:
        ciphertext = base64.b64decode(encoded_text.encode('ascii'))
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Decrypted text:")
        print("-" * 50)
        print(plaintext.decode('utf-8'))
        print("-" * 50)
    except Exception as e:
        print(f"Decrypt error: {e}")

def decrypt_text_long(encoded_text, private_key_name):
    """Decrypt long text hybrid - same format as short"""
    private_key = load_private_key(private_key_name)
    if private_key is None:
        return
    
    try:
        packed = base64.b64decode(encoded_text.encode('ascii'))
        
        # Unpack: [aes_key_size][encrypted_aes_key][iv][ciphertext]
        aes_key_size = struct.unpack('>I', packed[:4])[0]
        pos = 4
        encrypted_aes_key = packed[pos:pos + aes_key_size]
        pos += aes_key_size
        iv = packed[pos:pos + 16]
        ciphertext = packed[pos + 16:]
        
        # Decrypt AES key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        pad_len = plaintext_padded[-1]
        plaintext = plaintext_padded[:-pad_len]
        
        print("Decrypted text:")
        print("-" * 50)
        print(plaintext.decode('utf-8'))
        print("-" * 50)
        
    except Exception as e:
        print(f"Decrypt error: {e}")

def encrypt_file(filename, public_key_name):
    """Encrypt file with hybrid encryption"""
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return
    
    public_key = load_public_key(public_key_name)
    if public_key is None:
        return
    
    print(f"Encrypting {filename}...")
    
    # Generate AES key and IV
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    
    # Read and encrypt file with AES
    with open(filename, 'rb') as f:
        plaintext = f.read()
    
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len] * pad_len)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    
    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Save: [encrypted_aes_key_size][encrypted_aes_key][iv][ciphertext]
    output_filename = filename + ".encrypted"
    with open(output_filename, 'wb') as f:
        f.write(struct.pack('>I', len(encrypted_aes_key)))
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(ciphertext)
    
    print(f"Encrypted file saved: {output_filename}")

def decrypt_file(filename, private_key_name):
    """Decrypt file with hybrid decryption"""
    private_key = load_private_key(private_key_name)
    if private_key is None:
        return
    
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return
    
    print(f"Decrypting {filename}...")
    
    with open(filename, 'rb') as f:
        aes_key_size = struct.unpack('>I', f.read(4))[0]
        encrypted_aes_key = f.read(aes_key_size)
        iv = f.read(16)
        ciphertext = f.read()
    
    # Decrypt AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt file
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    pad_len = plaintext_padded[-1]
    plaintext = plaintext_padded[:-pad_len]
    
    output_filename = filename.replace(".encrypted", "")
    with open(output_filename, 'wb') as f:
        f.write(plaintext)
    
    print(f"Decrypted file saved: {output_filename}")

# === NEW SIGNING FUNCTIONS ===
def sign_text_short(plaintext, private_key_name):
    """Sign short text with RSA-PSS - output to stdout with delimiters"""
    private_key = load_private_key(private_key_name)
    if private_key is None:
        return
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    signature = private_key.sign(
        plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    encoded = base64.b64encode(signature).decode('ascii')
    print("-------")
    print("sign")
    print("-------")
    print(encoded)
    print("-------")

def sign_file(filename, private_key_name):
    """Sign file - create .sig file with SHA256 hash + RSA-PSS signature"""
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return
    
    private_key = load_private_key(private_key_name)
    if private_key is None:
        return
    
    print(f"Signing {filename}...")
    
    # Compute SHA256 hash of file
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    file_hash = digest.finalize()
    
    # Sign the hash
    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Save signature file: [signature_size][signature]
    sig_filename = filename + ".sig"
    with open(sig_filename, 'wb') as f:
        f.write(struct.pack('>I', len(signature)))
        f.write(signature)
    
    print(f"Signature saved: {sig_filename}")

def verify_text_short(plaintext, encoded_signature, public_key_name):
    """Verify short text signature"""
    public_key = load_public_key(public_key_name)
    if public_key is None:
        return
    
    try:
        signature = base64.b64decode(encoded_signature.encode('ascii'))
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        public_key.verify(
            signature,
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature VALID")
    except Exception as e:
        print("Signature INVALID")

def verify_file(filename, sig_filename, public_key_name):
    """Verify file signature"""
    public_key = load_public_key(public_key_name)
    if public_key is None:
        return
    
    if not os.path.exists(filename) or not os.path.exists(sig_filename):
        print("Error: File or signature file not found")
        return
    
    try:
        # Load signature
        with open(sig_filename, 'rb') as f:
            sig_size = struct.unpack('>I', f.read(4))[0]
            signature = f.read(sig_size)
        
        # Compute file hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                digest.update(chunk)
        file_hash = digest.finalize()
        
        # Verify
        public_key.verify(
            signature,
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature VALID")
    except Exception as e:
        print("Signature INVALID")

def main():
    parser = argparse.ArgumentParser(description="RSA Encryption & Signing Toolkit")
    parser.add_argument('key_name', nargs='?', help='Key name (used by all encrypt/decrypt/sign/verify commands)')
    
    parser.add_argument('--generate-keys', '-gk', nargs='?', metavar='NAME', 
                       help='Generate key pair (default: "default")')
    parser.add_argument('--key-size', '-k', type=int, default=2048, 
                       help='Key size (default: 2048)')
    
    # Encryption
    parser.add_argument('--encrypt-text', '-et', nargs=argparse.REMAINDER,
                       help='Encrypt short TEXT (RSA only, max ~190 bytes)')
    parser.add_argument('--decrypt-text', '-dt', nargs=argparse.REMAINDER,
                       help='Decrypt short TEXT (RSA only)')
    parser.add_argument('--encrypt-long', '-el', nargs=argparse.REMAINDER,
                       help='Encrypt long TEXT (hybrid AES+RSA, same format)')
    parser.add_argument('--decrypt-long', '-dl', nargs=argparse.REMAINDER,
                       help='Decrypt long TEXT (hybrid AES+RSA, same format)')
    parser.add_argument('--encrypt-file', '-ef', metavar='FILE',
                       help='Encrypt FILE (hybrid AES+RSA)')
    parser.add_argument('--decrypt-file', '-df', metavar='FILE',
                       help='Decrypt FILE (hybrid AES+RSA)')
    
    # Signing
    parser.add_argument('--sign-text', '-st', nargs=argparse.REMAINDER,
                       help='Sign short TEXT (RSA-PSS, copy-paste format)')
    parser.add_argument('--sign-file', '-sf', metavar='FILE',
                       help='Sign FILE (SHA256+RSA-PSS, creates FILE.sig)')
    parser.add_argument('--verify-text', '-vt', nargs=3, metavar=('TEXT', 'SIGNATURE', 'PUBKEY'),
                       help='Verify TEXT SIGNATURE with PUBKEY')
    parser.add_argument('--verify-file', '-vf', nargs=3, metavar=('FILE', 'FILE.sig', 'PUBKEY'),
                       help='Verify FILE with FILE.sig using PUBKEY')
    
    args = parser.parse_args()
    
    if args.generate_keys:
        name = args.generate_keys or "default"
        private_key, public_key = generate_rsa_keypair(args.key_size)
        if save_private_key(private_key, name):
            save_public_key(public_key, name)
    
    elif args.key_name:
        key_name = args.key_name
        
        # Encryption/Decryption
        if args.encrypt_text:
            text = ' '.join(args.encrypt_text)
            encrypt_text_short(text, key_name)
        elif args.decrypt_text:
            encoded_text = ' '.join(args.decrypt_text)
            decrypt_text_short(encoded_text, key_name)
        elif args.encrypt_long:
            text = ' '.join(args.encrypt_long)
            encrypt_text_long(text, key_name)
        elif args.decrypt_long:
            encoded_text = ' '.join(args.decrypt_long)
            decrypt_text_long(encoded_text, key_name)
        elif args.encrypt_file:
            encrypt_file(args.encrypt_file, key_name)
        elif args.decrypt_file:
            decrypt_file(args.decrypt_file, key_name)
        
        # Signing/Verification
        elif args.sign_text:
            text = ' '.join(args.sign_text)
            sign_text_short(text, key_name)
        elif args.sign_file:
            sign_file(args.sign_file, key_name)
        elif args.verify_text and len(args.verify_text) == 3:
            verify_text_short(args.verify_text[0], args.verify_text[1], args.verify_text[2])
        elif args.verify_file and len(args.verify_file) == 3:
            verify_file(args.verify_file[0], args.verify_file[1], args.verify_file[2])
        
        else:
            print_help(key_name)
    
    else:
        parser.print_help()

def print_help(key_name=None):
    """Print usage help"""
    print("# RSA Encryption & Signing Toolkit")
    print()
    print("# Security")
    print("Encryption: RSA-OAEP-SHA256 + AES-256-CBC")
    print("Signing:    RSA-PSS-SHA256 (modern, secure)")
    print("Security: 2048-bit RSA, 256-bit AES")
    print()
    if key_name:
        print(f"# Using key: {key_name}")
        print()
    print("# Generate keys")
    print('python rsaTK.py --generate-keys myKey')
    print('python rsaTK.py -k 4096 -gk mySecKey')
    print()
    print("# Short text (RSA only, max ~190 bytes)")
    print("## Encrypt")
    print(f'python rsaTK.py {key_name or "myKey"} -et "Secret message"')
    print("## Decrypt") 
    print(f'python rsaTK.py {key_name or "myKey"} -dt "BASE64_STRING"')
    print()
    print("# Sign/Verify text")
    print(f'python rsaTK.py {key_name or "myKey"} -st "Important message"')
    print(f'python rsaTK.py other_pubkey -vt "Important message" "BASE64_SIG"')
    print()
    print("# Long text (AES+RSA hybrid, unlimited size, SAME FORMAT!)")
    print("## Encrypt")
    print(f'python rsaTK.py {key_name or "myKey"} -el "Very long message..."')
    print("## Decrypt")
    print(f'python rsaTK.py {key_name or "myKey"} -dl "BASE64_HYBRID_STRING"')
    print()
    print("# Files (hybrid AES+RSA)")
    print("## Encrypt")
    print(f'python rsaTK.py {key_name or "myKey"} -ef budget.xlsx')
    print("## Decrypt")
    print(f'python rsaTK.py {key_name or "myKey"} -df budget.xlsx.encrypted')
    print()
    print("# Sign/Verify files")
    print(f'python rsaTK.py {key_name or "myKey"} -sf document.pdf')
    print(f'python rsaTK.py other_pubkey -vf document.pdf document.pdf.sig')

if __name__ == '__main__':
    main()
