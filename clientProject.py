import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import logging

# إعدادات السجل
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecureChatClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.symmetric_key = None
        self.iv = None
        
    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))
            logger.info(f"Connected to server {self.host}:{self.port}")
            
            # استقبال المفتاح العام من الخادم
            server_public_key_pem = self.client_socket.recv(2048)
            server_public_key = serialization.load_pem_public_key(
                server_public_key_pem,
                backend=default_backend()
            )
            
            # توليد مفتاح سري (جلسة) و IV
            self.symmetric_key = os.urandom(32)  # AES-256
            self.iv = os.urandom(16)  # Initialization Vector
            
            # تشفير المفتاح السري وإرساله للخادم******
            encrypted_symmetric_key = server_public_key.encrypt(
                self.symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.client_socket.send(encrypted_symmetric_key)
            
            # إرسال IV
            self.client_socket.send(self.iv)
            
            logger.info("Key exchange successful, connection is now secure")
            return True
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def send_message(self, message):
        if not self.symmetric_key:
            logger.error("Connection not secure, cannot send message")
            return False
            
        try:
            # تشفير الرسالة باستخدام AES
            cipher = Cipher(
                algorithms.AES(self.symmetric_key),
                modes.CFB(self.iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
            
            self.client_socket.send(encrypted_message)
            
            # استقبال الرد
            encrypted_response = self.client_socket.recv(1024)
            
            # فك تشفير الرد
            cipher = Cipher(
                algorithms.AES(self.symmetric_key),
                modes.CFB(self.iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            response = decryptor.update(encrypted_response) + decryptor.finalize()
            
            logger.info(f"Server response: {response.decode()}")
            return True
        except Exception as e:
            logger.error(f"Message sending error: {e}")
            return False
    
    def close(self):
        self.client_socket.close()
        logger.info("Connection closed")

if __name__ == "__main__":
    client = SecureChatClient()
    if client.connect():
        while True:
            message = input("Enter your message (or 'exit' to quit): ")
            if message.lower() == 'exit':
                break
            client.send_message(message)
        client.close()