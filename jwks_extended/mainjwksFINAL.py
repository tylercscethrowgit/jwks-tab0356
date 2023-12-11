from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import sqlite3
import base64
import json
import jwt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import datetime
from uuid import uuid4
from argon2 import PasswordHasher
from time import time


rate_limiting_dict = {}


hostName = "localhost"
serverPort = 8080
os.environ['NOT_MY_KEY'] = '1234567890123456'
STATIC_IV = os.urandom(16)  # 16 bytes IV for AES. In real-world use, this should be unique per encryption and stored securely.
DATABASE_NAME = "totally_not_my_privateKeys.db"

# Connect to the db and create tables
conn = sqlite3.connect(DATABASE_NAME)
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()
conn.close()


def rate_limiter(client_ip):
    current_time = time()
    window, request_count = rate_limiting_dict.get(client_ip, (current_time, 0))

    if current_time - window > 1:  # Reset every second
        rate_limiting_dict[client_ip] = (current_time, 1)
        return True
    elif request_count < 10:
        rate_limiting_dict[client_ip] = (window, request_count + 1)
        return True
    else:
        return False
    

# Function to encrypt the private key using AES
def encrypt_key_aes(private_key_pem, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB8(STATIC_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key_pem) + encryptor.finalize()
    return encrypted_key

def decrypt_key_aes(encrypted_key_pem, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB8(STATIC_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key_pem) + decryptor.finalize()
    return decrypted_key

# Function to save the generated private keys to db
def save_key_to_db(key, expiration):
    # Convert the key to PEM format
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Fetch and prepare the AES key
    aes_key = os.environ.get('NOT_MY_KEY')
    if not aes_key:
        raise ValueError("AES encryption key NOT_MY_KEY not found in environment variables")
    aes_key_bytes = aes_key.encode()  # Convert the AES key to bytes

    # Check the length of the AES key
    if len(aes_key_bytes) not in [16, 32]:
        raise ValueError("Invalid AES key length")

    # Encrypt the private key
    encrypted_pem = encrypt_key_aes(pem, aes_key_bytes)

    # Save the encrypted key to the database
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, expiration))
    conn.commit()
    conn.close()



# Test encryption and decryption
test_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pem = test_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

encrypted_pem = encrypt_key_aes(pem, os.environ['NOT_MY_KEY'].encode())
decrypted_pem = decrypt_key_aes(encrypted_pem, os.environ['NOT_MY_KEY'].encode())

assert pem == decrypted_pem, "Encryption/Decryption process failed"



# Generate private keys, save them
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save_key_to_db(private_key, int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp()))
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save_key_to_db(expired_key, int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).timestamp()))

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return


    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        # Handling user registration at /register endpoint
        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = json.loads(self.rfile.read(content_length))
            username = post_data['username']
            email = post_data['email']

            # Generate a UUIDv4 password and hash it
            password = str(uuid4())
            ph = PasswordHasher()
            password_hash = ph.hash(password)

            # Save the user in the database
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", 
                           (username, password_hash, email))
            conn.commit()
            conn.close()

            # Return the password to the user
            self.send_response(201)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'password': password}
            self.wfile.write(json.dumps(response).encode())
            return
        
        if parsed_path.path == "/auth":
            client_ip = self.client_address[0]
            if not rate_limiter(client_ip):
                self.send_response(429)  # Too Many Requests
                self.end_headers()
                return
            try:
                with sqlite3.connect(DATABASE_NAME) as conn:
                    cursor = conn.cursor()
                    if 'expired' in params:
                        cursor.execute("SELECT key FROM keys WHERE exp <= ?", (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
                    else:
                        cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
                    row = cursor.fetchone()

                    if not row:
                        self.send_response(200)
                        self.end_headers()
                        return

                    encrypted_pem_key = row[0]
                    aes_key = os.environ.get('NOT_MY_KEY').encode()  # Convert to bytes
                    decrypted_pem_key = decrypt_key_aes(encrypted_pem_key, aes_key)
                    headers = {"kid": str(row[0])}
                    token_payload = {
                        "user": "username",
                        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                    }
                    if 'expired' in params:
                        token_payload["exp"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)

                    encoded_jwt = jwt.encode(token_payload, decrypted_pem_key, algorithm="RS256", headers=headers)
                    
                    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                    user_row = cursor.fetchone()
                    user_id = user_row[0] if user_row else None

                    # Log the authentication request
                    request_ip = self.client_address[0]
                    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
                    conn.commit()

                    # Successful authentication response
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(bytes(encoded_jwt, "utf-8"))

            except Exception as e:
                print(f"Error in /auth: {e}")
                self.send_response(500)  # Internal Server Error
                self.end_headers()


                
        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            conn = sqlite3.connect(DATABASE_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
            valid_keys = cursor.fetchall()
            conn.close()
            
            keys = {"keys": []}
            for row in valid_keys:
                key = serialization.load_pem_private_key(row[0], None)
                numbers = key.private_numbers()
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(row[0]),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e)
                })

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return



if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
