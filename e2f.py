import hashlib
import time

def measurePbkdf2Iterations(password, salt, duration=1.0):
    start_time = time.time()
    iterations = 1000
    while True:
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
        elapsed_time = time.time() - start_time
        if elapsed_time >= duration:
            return iterations, elapsed_time
        iterations += 1000

password = "password"
salt = b"some_salt"
iterations, elapsed_time = measurePbkdf2Iterations(password, salt)
print(f"PBKDF2 iterations: {iterations} took {elapsed_time:.2f} seconds")
