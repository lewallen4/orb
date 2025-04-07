import socket
import select
import time
import os
import random
import logging
import pyaudio
import threading
from collections import deque
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
import struct
import hashlib
import argparse

class OrbHost:
    def __init__(self, port, name=None, enable_encryption=True):
        # Participant tracking
        self.participants = {}  # {address: name}
        self.host_name = name if name else self.generate_orb_name()
        
        # Encryption state
        self.encryption_enabled = enable_encryption
        self.session_keys = {}
        self.key_rotation_interval = 60
        self.last_key_rotation = 0
        
        # Configure logging
        self.setup_logging()
        
        # Audio setup
        self.pyaudio = pyaudio.PyAudio()
        self.input_stream = None
        self.output_stream = None
        self.selected_input_idx = 0
        self.selected_output_idx = 0
        
        # Network setup
        self.socket = None
        self.port = port
        self.running = False
        self.connections = []
        
        # Transmission state
        self.transmitting = False
        self.last_activity = 0
        self.activity_history = deque(maxlen=10)
        
        # Generate host key pair if encryption is enabled
        if self.encryption_enabled:
            self.host_public_key, self.host_private_key = self.generate_kyber_keys()
        
        self.log(f"ORB Host initialized on port {port} with name '{self.host_name}'")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='orb_host.log',
            filemode='w'
        )
        self.logger = logging.getLogger('ORB_HOST')
        
    def log(self, message, level='info'):
        getattr(self.logger, level)(message)
        print(f"[{level.upper()}] {message}")
    
    def generate_orb_name(self):
        adjectives = ["Eldritch", "Phantom", "Wraith", "Specter", "Haunted", "Cursed"]
        nouns = ["Chamber", "Void", "Abyss", "Crypt", "Shroud", "Wraith"]
        return f"{random.choice(adjectives)}-{random.choice(nouns)}"
    
    def generate_kyber_keys(self):
        """Generate Kyber key pair for post-quantum key exchange"""
        try:
            public_key, private_key = generate_keypair()
            return public_key, private_key
        except Exception as e:
            self.log(f"Error generating Kyber keys: {str(e)}", 'error')
            raise
    
    def encrypt_audio_data(self, data, key):
        """Encrypt audio data using AES-256-GCM"""
        try:
            # Generate a random nonce
            nonce = get_random_bytes(12)
            
            # Create cipher object and encrypt the data
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            # Combine nonce + tag + ciphertext
            encrypted_data = nonce + tag + ciphertext
            return encrypted_data
        except Exception as e:
            self.log(f"Error encrypting audio data: {str(e)}", 'error')
            raise
    
    def decrypt_audio_data(self, encrypted_data, key):
        """Decrypt audio data using AES-256-GCM"""
        try:
            # Split the encrypted data into components
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher object and decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data
        except Exception as e:
            self.log(f"Error decrypting audio data: {str(e)}", 'error')
            raise
    
    def perform_key_exchange(self, addr, is_host=True):
        """Perform post-quantum key exchange with a peer"""
        try:
            # Host generates key pair and sends public key
            public_key, private_key = self.generate_kyber_keys()
            
            # Send public key to client
            self.socket.sendto(b'ORB_KEY_EXCHANGE' + public_key, addr)
            self.log(f"Sent public key to {addr}")
            
            # Wait for encapsulated key from client
            ready = select.select([self.socket], [], [], 5.0)
            if not ready[0]:
                raise TimeoutError("Key exchange timeout")
            
            data, _ = self.socket.recvfrom(1024)
            if not data.startswith(b'ORB_ENCAPSULATED'):
                raise ValueError("Invalid key exchange response")
            
            # Extract encapsulated key
            encapsulated_key = data[len('ORB_ENCAPSULATED'):]
            
            # Decapsulate to get shared secret
            shared_secret = decrypt(encapsulated_key, private_key)
            
            # Derive AES key from shared secret
            aes_key = hashlib.sha256(shared_secret).digest()
            
            # Store the session key for this client
            self.session_keys[addr] = {
                'aes_key': aes_key,
                'last_used': time.time()
            }
            
            self.log(f"Key exchange completed with {addr}")
            return aes_key
            
        except Exception as e:
            self.log(f"Key exchange failed: {str(e)}", 'error')
            raise
    
    def rotate_keys_if_needed(self):
        """Rotate session keys if the rotation interval has passed"""
        if not self.encryption_enabled:
            return
        
        current_time = time.time()
        if current_time - self.last_key_rotation > self.key_rotation_interval:
            self.log("Rotating session keys...")
            
            # Rotate keys for all connected clients
            for addr in list(self.session_keys.keys()):
                try:
                    new_key = self.perform_key_exchange(addr, is_host=True)
                    self.session_keys[addr]['aes_key'] = new_key
                    self.session_keys[addr]['last_used'] = current_time
                except Exception as e:
                    self.log(f"Failed to rotate key for {addr}: {str(e)}", 'warning')
                    del self.session_keys[addr]
            
            self.last_key_rotation = current_time
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            self.log(f"Could not determine local IP: {str(e)}", 'warning')
            return "127.0.0.1"
            
    def get_public_ip(self):
        """Get public IP using a simple service"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect(("api.ipify.org", 80))
                s.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n")
                response = s.recv(1024)
                return response.decode().split("\r\n\r\n")[1].strip()
        except Exception:
            return None
            
    def help_nat_traversal(self, port):
        """Attempt to help with NAT traversal by sending packets to common public STUN servers"""
        stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302),
            ("stun.voipbuster.com", 3478),
            ("stun.ekiga.net", 3478)
        ]
        
        for server in stun_servers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.sendto(b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12), server)
                s.recvfrom(1024)
                s.close()
            except:
                continue
    
    def broadcast_participant_list(self):
        """Send the current participant list to all connected clients"""
        try:
            # Include host in participant list
            full_participants = {**self.participants}
            host_addr = ('0.0.0.0', self.port)
            if host_addr not in full_participants:
                full_participants[host_addr] = self.host_name
                
            participant_data = str(full_participants).encode()
            
            for addr in full_participants.keys():
                if addr == host_addr:  # Skip sending to self
                    continue
                try:
                    # Send host name first
                    self.socket.sendto(b'ORB_HOST_NAME' + self.host_name.encode(), addr)
                    # Then send participant list
                    self.socket.sendto(b'ORB_PARTICIPANTS' + participant_data, addr)
                except Exception as e:
                    self.log(f"Error sending participant info to {addr}: {str(e)}", 'error')
        except Exception as e:
            self.log(f"Error broadcasting participant list: {str(e)}", 'error')
    
    def start(self):
        try:
            # Setup socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                self.socket.bind(('0.0.0.0', self.port))
                # Start NAT traversal help in background
                threading.Thread(target=self.help_nat_traversal, args=(self.port,), daemon=True).start()
                
                # Show both public and local IP if available
                public_ip = self.get_public_ip()
                if public_ip:
                    self.log(f"Hosting ORB '{self.host_name}'\nPublic IP: {public_ip}\nLocal IP: {self.get_local_ip()}")
                else:
                    self.log(f"Hosting ORB '{self.host_name}'\nLocal IP: {self.get_local_ip()}\n(Public IP detection failed)")
                
                self.running = True
                
                # Start network thread
                self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
                self.receive_thread.start()
                
                self.log("ORB Host started successfully")
                
                # Keep the main thread alive
                while self.running:
                    time.sleep(1)
                
            except Exception as e:
                raise ConnectionError(f"Failed to bind to port {self.port}: {str(e)}")
        
        except KeyboardInterrupt:
            self.log("Shutting down ORB Host...")
            self.stop()
        except Exception as e:
            self.log(f"Error starting ORB Host: {str(e)}", 'error')
            self.stop()
    
    def stop(self):
        self.log("Stopping ORB Host...")
        self.running = False
        
        try:
            if self.socket:
                self.socket.close()
                self.log("Socket closed")
        except Exception as e:
            self.log(f"Error closing socket: {str(e)}", 'error')
        
        # Clear encryption state
        self.session_keys.clear()
        self.participants.clear()
        
        self.log("ORB Host stopped")
    
    def receive_loop(self):
        self.log("Receive loop started")
        while self.running:
            try:
                ready = select.select([self.socket], [], [], 0.1)
                if ready[0]:
                    data, addr = self.socket.recvfrom(1024*8)
                    
                    # Handle verification requests
                    if data == b'ORB_VERIFY':
                        self.socket.sendto(b'ORB_ACK', addr)
                        continue
                    
                    # Handle client name announcement
                    if data.startswith(b'ORB_CLIENT_NAME'):
                        client_name = data[len('ORB_CLIENT_NAME'):].decode()
                        self.participants[addr] = client_name
                        self.log(f"Client {addr} set name to: {client_name}")
                        self.broadcast_participant_list()
                        continue
                    
                    # Handle new connections
                    if not any(c[0] == addr for c in self.connections):
                        self.connections.append((addr, None))
                        if addr not in self.participants:
                            # Only generate name if client didn't provide one
                            participant_name = f"Guest-{random.randint(100,999)}"
                            self.participants[addr] = participant_name
                            self.log(f"New connection from {addr} as {participant_name}")
                        
                        # Send host name and participant list to new client
                        self.broadcast_participant_list()
                        
                        # If encryption is enabled, perform key exchange
                        if self.encryption_enabled:
                            self.perform_key_exchange(addr, is_host=True)
                    
                    # Handle key exchange initiation from client
                    if data.startswith(b'ORB_KEY_EXCHANGE') and self.encryption_enabled:
                        try:
                            # Extract public key and perform key exchange
                            public_key = data[len('ORB_KEY_EXCHANGE'):]
                            
                            # Generate encapsulated key and shared secret
                            encapsulated_key, shared_secret = encrypt(public_key)
                            
                            # Send encapsulated key to client
                            self.socket.sendto(b'ORB_ENCAPSULATED' + encapsulated_key, addr)
                            
                            # Derive AES key from shared secret
                            aes_key = hashlib.sha256(shared_secret).digest()
                            
                            # Store the session key
                            self.session_keys[addr] = {
                                'aes_key': aes_key,
                                'last_used': time.time()
                            }
                            
                            self.log(f"Key exchange completed with {addr}")
                        except Exception as e:
                            self.log(f"Key exchange failed: {str(e)}", 'error')
                        continue
                    
                    # Handle encapsulated key from client (host mode)
                    if data.startswith(b'ORB_ENCAPSULATED') and self.encryption_enabled:
                        try:
                            # Extract encapsulated key
                            encapsulated_key = data[len('ORB_ENCAPSULATED'):]
                            
                            # Decapsulate to get shared secret
                            shared_secret = decrypt(encapsulated_key, self.host_private_key)
                            
                            # Derive AES key from shared secret
                            aes_key = hashlib.sha256(shared_secret).digest()
                            
                            # Store the session key for this client
                            self.session_keys[addr] = {
                                'aes_key': aes_key,
                                'last_used': time.time()
                            }
                            
                            self.log(f"Key exchange completed with {addr}")
                        except Exception as e:
                            self.log(f"Key exchange failed: {str(e)}", 'error')
                        continue
                    
                    # Decrypt data if encryption is enabled
                    decrypted_data = data
                    if self.encryption_enabled:
                        try:
                            if addr in self.session_keys:
                                decrypted_data = self.decrypt_audio_data(data, self.session_keys[addr]['aes_key'])
                                self.session_keys[addr]['last_used'] = time.time()
                            else:
                                # New client - initiate key exchange
                                self.perform_key_exchange(addr, is_host=True)
                                continue
                        except Exception as e:
                            self.log(f"Decryption failed: {str(e)}", 'warning')
                            continue
                    
                    # Broadcast to all other connections
                    for connection in [c for c in self.connections if c[0] != addr]:
                        try:
                            # Encrypt data for each client with their own key
                            if self.encryption_enabled and connection[0] in self.session_keys:
                                encrypted_data = self.encrypt_audio_data(decrypted_data, self.session_keys[connection[0]]['aes_key'])
                                self.socket.sendto(encrypted_data, connection[0])
                            else:
                                self.socket.sendto(decrypted_data, connection[0])
                        except Exception as e:
                            self.log(f"Error sending to {connection}: {str(e)}", 'error')
                            self.connections.remove(connection)
                            if connection[0] in self.participants:
                                del self.participants[connection[0]]
                            self.broadcast_participant_list()
                    
                    self.last_activity = time.time()
                    self.activity_history.append(("receive", time.time()))
                    
                    # Rotate keys if needed
                    self.rotate_keys_if_needed()
                
            except (socket.timeout, BlockingIOError):
                continue
            except OSError as e:
                if self.running:
                    # Clean up disconnected clients
                    for addr in list(self.participants.keys()):
                        try:
                            self.socket.sendto(b'ORB_PING', addr)
                        except:
                            # Client is disconnected
                            if addr in self.participants:
                                del self.participants[addr]
                            self.connections = [c for c in self.connections if c[0] != addr]
                            if addr in self.session_keys:
                                del self.session_keys[addr]
                            self.log(f"Removed disconnected client: {addr}")
                            self.broadcast_participant_list()
                break
            except Exception as e:
                if self.running:
                    self.log(f"Unexpected error in receive loop: {str(e)}", 'error')
                    raise

def main():
    parser = argparse.ArgumentParser(description='ORB Host - Secure Voice Communication Server')
    parser.add_argument('-p', '--port', type=int, default=12345, help='Port to listen on (default: 12345)')
    parser.add_argument('-n', '--name', type=str, help='Name for this ORB host')
    parser.add_argument('--no-encryption', action='store_true', help='Disable encryption (not recommended)')
    
    args = parser.parse_args()
    
    host = OrbHost(
        port=args.port,
        name=args.name,
        enable_encryption=not args.no_encryption
    )
    
    try:
        host.start()
    except KeyboardInterrupt:
        host.stop()

if __name__ == "__main__":
    main()