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
        if offset >= len(data):
            break
        field_id = data[offset]
        offset += 1

        # Read field length (2 bytes, little-endian)
        if offset + 2 > len(data):
            break
        length_bytes = data[offset:offset+2]
        field_length = struct.unpack('<H', length_bytes)[0]
        offset += 2

        if field_id == 0:  # End of header
            encrypted_data = data[offset:]
            return header_info, encrypted_data

        # Read field data
        if offset + field_length > len(data):
            break
        field_data = data[offset:offset+field_length]
        offset += field_length

        if field_id == 4:  # master seed
            header_info['master_seed'] = field_data
        elif field_id == 5:  # transform seed
            header_info['transform_seed'] = field_data
        elif field_id == 6:  # transform rounds
            if len(field_data) >= 8:  # KeePass 2.x uses 8 bytes for rounds
                header_info['transform_rounds'] = struct.unpack('<Q', field_data[:8])[0]
            elif len(field_data) >= 4:  # Fallback to 4 bytes
                header_info['transform_rounds'] = struct.unpack('<I', field_data[:4])[0]
        elif field_id == 7:  # encryption IV
            header_info['encryption_iv'] = field_data
        elif field_id == 9:  # stream start bytes
            header_info['stream_start_bytes'] = field_data
    
    raise ValueError("No end of header field found")

def derive_key(password, master_seed, transform_seed, transform_rounds):
    """Derive the AES key from the password using the KeePass key derivation process"""
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Step 1: Hash the password with SHA-256
    password_hash = hashlib.sha256(password_bytes).digest()
    
    # Ensure we have exactly 32 bytes for AES-256
    if len(password_hash) != 32:
        password_hash = password_hash[:32].ljust(32, b'\x00')

    # Step 2: Transform the password hash using AES-ECB with transform_seed
    # Ensure transform_seed is exactly 32 bytes for AES-256
    if len(transform_seed) != 32:
        if len(transform_seed) < 32:
            transform_seed = transform_seed.ljust(32, b'\x00')
        else:
            transform_seed = transform_seed[:32]
    
    cipher = AES.new(transform_seed, AES.MODE_ECB)
    
    # Apply AES transformation for transform_rounds times
    transformed = password_hash
    for _ in range(transform_rounds):
        transformed = cipher.encrypt(transformed)

    # Step 3: Hash the transformed result
    transformed_hash = hashlib.sha256(transformed).digest()

    # Step 4: Final key = SHA-256(master_seed || transformed_hash)
    final_key = hashlib.sha256(master_seed + transformed_hash).digest()

    return final_key

def try_decrypt(encrypted_data, key, iv, expected_start_bytes):
    """Try to decrypt the first block and check if it matches the stream start bytes"""
    try:
        # Ensure we have enough data to decrypt
        if len(encrypted_data) < 32:
            return False
            
        # Ensure IV is the correct length (16 bytes for AES)
        if len(iv) != 16:
            if len(iv) < 16:
                iv = iv.ljust(16, b'\x00')
            else:
                iv = iv[:16]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data[:32])
        
        # Compare with expected stream start bytes
        expected_len = len(expected_start_bytes)
        return decrypted[:expected_len] == expected_start_bytes
        
    except Exception as e:
        return False

def brute_force_attack(header_info, encrypted_data):
    """Perform brute force attack on numeric passwords with lengths 1 to 4 digits"""
    # Check if we have all required header fields
    required_fields = ['master_seed', 'transform_seed', 'transform_rounds', 'encryption_iv', 'stream_start_bytes']
    for field in required_fields:
        if field not in header_info:
            print(f"Missing required header field: {field}")
            return None
    
    master_seed = header_info['master_seed']
    transform_seed = header_info['transform_seed']
    transform_rounds = header_info['transform_rounds']
    encryption_iv = header_info['encryption_iv']
    stream_start_bytes = header_info['stream_start_bytes']
    
    print(f"Starting brute force attack...")
    print(f"Transform rounds: {transform_rounds}")
    print(f"Master seed length: {len(master_seed)} bytes")
    print(f"Transform seed length: {len(transform_seed)} bytes")
    print(f"Stream start bytes length: {len(stream_start_bytes)} bytes")
    
    total_attempts = 0
    
    # Generate all numeric combinations from length 1 to 4 digits
    for length in range(1, 5):  # Lengths from 1 to 4 digits
        print(f"Trying {length}-digit passwords...")
        
        for password_num in range(10**length):
            password = str(password_num).zfill(length)  # Zero-pad to specified length
            total_attempts += 1
            
            if total_attempts % 1000 == 0:
                print(f"Tried {total_attempts} passwords, current: {password}")
            
            try:
                key = derive_key(password, master_seed, transform_seed, transform_rounds)
                
                # Try to decrypt and verify
                if try_decrypt(encrypted_data, key, encryption_iv, stream_start_bytes):
                    print(f"SUCCESS! Password found: {password}")
                    return password
                    
            except Exception as e:
                # Continue with next password if current one fails
                continue
    
    print(f"Brute force completed. Tried {total_attempts} passwords.")
    return None

def main():
    filepath = './databases/Mwanga.kdbx'
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        print(f"Loaded {len(data)} bytes from {filepath}")
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
   
    if len(data) < 12:
        print("File too small to be a valid KeePass database")
        return
    
    # Validate KeePass signature
    sig1 = struct.unpack('<I', data[0:4])[0]
    sig2 = struct.unpack('<I', data[4:8])[0]
    version = struct.unpack('<I', data[8:12])[0]
    
    print(f"Signature 1: 0x{sig1:08x}")
    print(f"Signature 2: 0x{sig2:08x}")
    print(f"Version: 0x{version:08x}")
  
    if sig1 != 0x9aa2d903 or sig2 != 0xb54bfb67:
        print("Invalid KeePass signature")
        return

    # Skip signature and version (first 12 bytes)
    header_data = data[12:]
    
    try:
        header_info, encrypted_data = parse_header(header_data)
        
        print(f"Header parsed successfully")
        print(f"Encrypted data length: {len(encrypted_data)} bytes")
        
        # Start brute force attack
        password = brute_force_attack(header_info, encrypted_data)
        
        if password:
            print(f"\n=== CRACKED ===")
            print(f"Password: {password}")
        else:
            print("\nFailed to crack the database with 1-4 digit numeric passwords")
            
    except Exception as e:
        print(f"Error during processing: {e}")
        import traceback
        traceback.print_exc()
        return

if __name__ == "__main__":
    main()