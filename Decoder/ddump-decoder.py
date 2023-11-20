#!/usr/bin/env python3

# File name          : ddump-decoder.py
# Author             : FatCyclone
# Date created       : 19/11/2023


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import argparse

def parseArgs():
    parser = argparse.ArgumentParser(add_help=True, description="DDump file decryptor")
    parser.add_argument("-k", "--key", required=True, type=str,help="Key for AES CBC used in ddump")
    parser.add_argument("-i", "--iv", required=True, type=str, help="IV for AES CBC used in ddump")
    parser.add_argument("-f", "--file", required=True, type=str, help="Dumpfile exported with ddump")
    parser.add_argument("-d", "--destfile", required=True, type=str, help="Decrypted file destination")
    args = parser.parse_args()
    return args
    

def decrypt_aes(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def main():
    
    args = parseArgs()
    	
    
    key_str = args.key
    iv_str = args.iv
    
    # Convert the key string to bytes using ASCII encoding
    key = key_str.encode('ascii')
    iv = iv_str.encode('ascii')

    # Read the encrypted mini dump file
    with open(args.file, 'rb') as file:
        encrypted_data = file.read()

    # Decrypt the data
    decrypted_data = decrypt_aes(encrypted_data, key, iv)

    # Save the decrypted data to a new file
    with open(args.destfile, 'wb') as file:
        file.write(decrypted_data)

    print("Decryption complete. Decrypted data saved to "+args.destfile+".")

if __name__ == "__main__":
    main()
