import hashlib
from Crypto.Cipher import AES
import struct
import os

def parse_header(data):
    """Parse KeePass header fields and return extracted information"""
    offset = 0
    header_info = {}
    while offset < len(data):
        # Read field ID (1 byte)
        field_id = data[offset]
        offset += 1

        # Read field length (2 bytes, little-endian)
        length_bytes = data[offset:offset+2]
        field_length = struct.unpack('<H', length_bytes)[0]
        offset += 2

        if field_id == 0:  # End of header
            encrypted_data = data[offset:]
            return header_info, encrypted_data

        # Read field data
        field_data = data[offset:offset+field_length]
        offset += field_length

        if field_id == 4:  # master seed
            header_info['master_seed'] = field_data
        elif field_id == 5:  # transform seed
            header_info['transform_seed'] = field_data
        elif field_id == 6:  # transform rounds
            header_info['transform_rounds'] = struct.unpack('<I', field_data[:4])[0]
        elif field_id == 7:  # encryption IV
            header_info['encryption_iv'] = field_data
        elif field_id == 9:  # stream start bytes
            header_info['stream_start_bytes'] = field_data
    
    raise ValueError("No end of header field found")

def derive_key(password, master_seed, transform_seed, transform_rounds):
    """Derive the AES key from the password using the KeePass key derivation process"""
    # Step 1: Convert password to bytes (treating it as a numeric password)
    password_bytes = password.to_bytes((password.bit_length() + 7) // 8, byteorder='big')
    
    # Derive credentials using SHA-256(SHA-256(password))
    credentials = hashlib.sha256(hashlib.sha256(password_bytes).digest()).digest()

    # Ensure credentials are 32 bytes
    if len(credentials) < 32:
        credentials = credentials.ljust(32, b'\x00')

    # AES transformation with the transform_seed, ECB mode
    cipher = AES.new(transform_seed, AES.MODE_ECB)

    # Apply AES transformation for transform_rounds times
    transformed = credentials
    for _ in range(transform_rounds):
        transformed = cipher.encrypt(transformed)

    # Step 2: Derive transformed credentials using SHA-256(transformed)
    transformed_credentials = hashlib.sha256(transformed).digest()

    # Step 3: Final key = SHA-256(master_seed || transformed_credentials)
    final_key = hashlib.sha256(master_seed + transformed_credentials).digest()

    return final_key

def try_decrypt(encrypted_data, key, iv, expected_start_bytes):
    """Try to decrypt the first 32 bytes of the database and check if it matches the stream start bytes"""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data[:32])  # Only decrypt the first 32 bytes
        return decrypted == expected_start_bytes
    except Exception:
        return False


def brute_force_attack(header_info, encrypted_data):
    """Perform brute force attack on numeric passwords with lengths 1 to 4 digits"""
    master_seed = header_info['master_seed']
    transform_seed = header_info['transform_seed']
    transform_rounds = header_info['transform_rounds']
    encryption_iv = header_info['encryption_iv']
    stream_start_bytes = header_info['stream_start_bytes']
    
    # Generate all numeric combinations from length 1 to 4 digits
    for length in range(1, 5):  # Lengths from 1 to 4 digits
        for password_num in range(10**length):  # Numbers from 0 to 9999 for current length
            password = f"{password_num:0{length}d}"  # Format to 1 to 4 digit number (e.g., 0, 00, 000, 0000)
            
            # Convert password to integer and then derive key
            password_int = int(password)  # Convert string to integer
            key = derive_key(password_int, master_seed, transform_seed, transform_rounds)

            # Try to decrypt and verify
            if try_decrypt(encrypted_data, key, encryption_iv, stream_start_bytes):
                return password
    
    return None



def main():
    filepath = './databases/Mwanga.kdbx'
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return
   
    if len(data) < 12:
        return
    
    # Validate KeePass signature
    sig1 = struct.unpack('<I', data[0:4])[0]
    sig2 = struct.unpack('<I', data[4:8])[0]
  
    if sig1 != 0x9aa2d903 or sig2 != 0xb54bfb67:
        return

    # Skip signature and version (first 12 bytes)
    header_data = data[12:]
    
    try:
        header_info, encrypted_data = parse_header(header_data)
        
        # Start brute force attack
        password = brute_force_attack(header_info, encrypted_data)
        
        if password:
            print(f"Password: {password}")
        else:
            print("Failed to crack the database")
            
    except Exception as e:
        return

if __name__ == "__main__":
    main()
