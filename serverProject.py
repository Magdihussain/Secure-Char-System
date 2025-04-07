import socket
import threading
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

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        
        # توليد زوج المفاتيح غير المتماثل
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"Server running on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"New connection from {client_address}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("Stopping server...")
            self.server_socket.close()
    
    def handle_client(self, client_socket, client_address):
        try:
            # إرسال المفتاح العام للعميل
            public_key_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(public_key_pem)
            
            # استقبال المفتاح السري المشفر من العميل
            encrypted_symmetric_key = client_socket.recv(2048)
            if not encrypted_symmetric_key:
                raise Exception("Failed to receive symmetric key")
                
            symmetric_key = self.private_key.decrypt(
                encrypted_symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # استقبال IV من العميل
            iv = client_socket.recv(16)
            
            self.clients[client_address] = (client_socket, symmetric_key, iv)
            logger.info(f"Secure connection established with {client_address}")
            
            while True:
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message:
                    break
                    
                # فك تشفير الرسالة باستخدام AES
                cipher = Cipher(
                    algorithms.AES(symmetric_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                message = decryptor.update(encrypted_message) + decryptor.finalize()
                
                logger.info(f"Message from {client_address}: {message.decode()}")
                
                # رد آلي
                response = f"Received your message: {message.decode()}"
                
                cipher = Cipher(
                    algorithms.AES(symmetric_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                encrypted_response = encryptor.update(response.encode()) + encryptor.finalize()
                
                client_socket.send(encrypted_response)
                
        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            if client_address in self.clients:
                del self.clients[client_address]
            logger.info(f"Connection closed with {client_address}")

if __name__ == "__main__":
    server = SecureChatServer()
    server.start()