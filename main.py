import hashlib
from Crypto.Cipher import AES
import struct
import os

def parse_header(data):
    """Parse KeePass header fields and return extracted information"""
    offset = 0
    header_fields = {}
    
    while True:
        field_id = data[offset]
        field_size = struct.unpack("<H", data[offset + 1:offset + 3])[0]
        field_data = data[offset + 3:offset + 3 + field_size]
        header_fields[field_id] = field_data
        offset += 3 + field_size
        if field_id == 0:
            break
    
    encrypted_data = data[offset:]
    return header_fields, encrypted_data

def derive_key(password, master_seed, transform_seed, transform_rounds):
    """Key derivation function - matches the working version exactly"""
    password_hash = hashlib.sha256(hashlib.sha256(password.encode()).digest()).digest()
    aes = AES.new(transform_seed, AES.MODE_ECB)
    transformed_credentials = password_hash
    for _ in range(transform_rounds):
        transformed_credentials = aes.encrypt(transformed_credentials)
    transformed_credentials = hashlib.sha256(transformed_credentials).digest()
    key = hashlib.sha256(master_seed + transformed_credentials).digest()
    return key

def decrypt_database(key, iv, encrypted_data):
    """Decrypt function - matches the working version exactly"""
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(encrypted_data)
    return decrypted_data

def brute_force_attack(header_fields, encrypted_data):
    """Perform brute force attack exactly like the working version"""
    # Extract relevant fields exactly like working version
    master_seed = header_fields[4]
    transform_seed = header_fields[5]
    transform_rounds = struct.unpack("<Q", header_fields[6])[0]
    iv = header_fields[7]
    stream_start_bytes = header_fields[9]
    
    print(f"Starting brute force attack...")
    print(f"Transform rounds: {transform_rounds}")
    print(f"Master seed length: {len(master_seed)} bytes")
    print(f"Transform seed length: {len(transform_seed)} bytes")
    print(f"Stream start bytes length: {len(stream_start_bytes)} bytes")
    
    # Brute force attack - exactly like working version
    tested_numbers = 0
    for password in range(10000):
        password_str = f"{password:04d}"
        tested_numbers += 1
        if tested_numbers % 1000 == 0:
            print(f"Tested {tested_numbers} passwords, still searching...")
        
        key = derive_key(password_str, master_seed, transform_seed, transform_rounds)
        decrypted_data = decrypt_database(key, iv, encrypted_data)
        if decrypted_data.startswith(stream_start_bytes):
            print(f"Password found: {password_str}")
            return password_str
    
    print(f"Brute force completed. Tried {tested_numbers} passwords.")
    return None

def main():
    # KeePass database file - get input like working version
    file_path = './databases/Appiah.kdbx'
    print(f"Using file path: {file_path}")
    
    try:
        # Read the database file
        with open(file_path, "rb") as f:
            db = f.read()
        print(f"Loaded {len(db)} bytes from {file_path}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Extracting header info - exactly like working version
    signature1 = struct.unpack("<I", db[0:4])[0]
    signature2 = struct.unpack("<I", db[4:8])[0]
    version = struct.unpack("<I", db[8:12])[0]
    
    print(f"Signature 1: 0x{signature1:08x}")
    print(f"Signature 2: 0x{signature2:08x}")
    print(f"Version: 0x{version:08x}")
    
    # Check if the database is a KeePass 2.x database
    if signature1 != 0x9AA2D903 or signature2 != 0xB54BFB67:
        print("Not a KeePass 2.x database")
        return
    
    try:
        # Read header fields - using working version's approach
        header_fields, encrypted_data = parse_header(db[12:])
        
        print(f"Header parsed successfully")
        print(f"Encrypted data length: {len(encrypted_data)} bytes")
        
        # Start brute force attack
        password = brute_force_attack(header_fields, encrypted_data)
        
        if password:
            print(f"\n=== SUCCESS ===")
            print(f"Password found: {password}")
        else:
            print("\nFailed to crack the database with 4-digit numeric passwords")
            
    except Exception as e:
        print(f"Error during processing: {e}")
        import traceback
        traceback.print_exc()
        return

if __name__ == "__main__":
    main()