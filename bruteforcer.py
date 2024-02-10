import itertools
import hashlib

def hash_password(password, hash_algorithm):
    if hash_algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        print("Unsupported hash algorithm")
        return None

def crack_password(hashed_password, charset, hash_algorithm):
    for length in range(1, len(hashed_password) + 1):
        for attempt in itertools.product(charset, repeat=length):
            attempt_str = ''.join(attempt)
            hashed_attempt = hash_password(attempt_str, hash_algorithm)

            if hashed_attempt == hashed_password:
                print(f"Password cracked: {attempt_str}")
                return

    print("Password not found.")

if __name__ == "__main__":
    hashed_password = input("Enter the hashed password: ")
    charset = input("Enter the character set: ")
    hash_algorithm = input("Enter the hash algorithm (md5, sha256, or sha512): ")

    crack_password(hashed_password, charset, hash_algorithm)

