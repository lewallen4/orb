import tkinter as tk
from tkinter import ttk, messagebox, font
import threading
import pyaudio
import socket
import random
import select
import time
import os
import logging
from collections import deque
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
import struct
import hashlib

class OrbApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ORB v1.3 (PQ-Encrypted)")
        self.root.geometry("700x900")
        self.root.minsize(650, 700)
        
        # Encryption state
        self.encryption_enabled = True
        self.session_keys = {}
        self.client_key = None
        self.key_rotation_interval = 60
        self.last_key_rotation = 0
        
        # Configure logging
        self.setup_logging()
        
        # Design constants
        self.BG_COLOR = "#121212"
        self.FG_COLOR = "#ffffff"
        self.ACCENT_COLOR = "#5e9cff"
        self.ERROR_COLOR = "#ff5e5e"
        self.SECONDARY_COLOR = "#252525"
        self.TERTIARY_COLOR = "#333333"
        self.TRANSMIT_COLOR = "#ff3b30"
        self.RECEIVE_COLOR = "#34c759"
        self.IDLE_COLOR = "#5e5ce6"
        self.ENCRYPTION_COLOR = "#af52de"
        self.DISABLED_COLOR = "#666666"
        
        # Configure styles
        self.root.configure(bg=self.BG_COLOR)
        self.custom_font = font.Font(family="Helvetica", size=12)
        self.title_font = font.Font(family="Helvetica", size=18, weight="bold")
        
        # Audio setup
        self.pyaudio = pyaudio.PyAudio()
        self.input_stream = None
        self.output_stream = None
        self.selected_input_idx = 0
        self.selected_output_idx = 0
        
        # Network setup
        self.socket = None
        self.host_mode = False
        self.running = False
        self.connections = []
        self.participant_names = {}
        self.host_name = ""
        self.client_name = ""
        
        # Transmission state
        self.transmitting = False
        self.space_pressed = False
        self.last_activity = 0
        self.activity_history = deque(maxlen=10)
        
        # UI variables
        self.status_var = tk.StringVar()
        self.status_var.set("ORB: Ready")
        self.host_ip_var = tk.StringVar()
        self.host_ip_var.set("")
        self.host_name_var = tk.StringVar()
        self.host_name_var.set("")
        self.client_name_var = tk.StringVar()
        self.client_name_var.set(self.generate_orb_name())
        
        self.setup_ui()
        self.refresh_devices()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='orb.log',
            filemode='w'
        )
        self.logger = logging.getLogger('ORB')
        
    def log(self, message, level='info'):
        getattr(self.logger, level)(message)
        print(f"[{level.upper()}] {message}")
        
    def setup_ui(self):
        # Main container
        main_frame = tk.Frame(self.root, bg=self.BG_COLOR, padx=20, pady=20)
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        # Header
        header_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header_frame, text="ORB", font=self.title_font, 
                bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=tk.LEFT)
        
        # Status indicator
        self.status_indicator = tk.Label(header_frame, text="●", font=("Courier", 14),
                                       bg=self.BG_COLOR, fg="#666666")
        self.status_indicator.pack(side=tk.RIGHT, padx=10)
        
        # Encryption indicator
        self.encryption_indicator = tk.Label(header_frame, text="🔒", 
                                           font=("Courier", 14),
                                           bg=self.BG_COLOR, fg=self.ENCRYPTION_COLOR)
        self.encryption_indicator.pack(side=tk.RIGHT, padx=5)
        
        # ASCII ORB display
        self.orb_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        self.orb_frame.pack(pady=20)
        
        self.orb_label = tk.Label(self.orb_frame, text=self.get_orb_art(), 
                                font=("Courier", 12), fg=self.IDLE_COLOR,
                                bg=self.BG_COLOR)
        self.orb_label.pack()
        
        # Bind orb click
        self.orb_label.bind("<Button-1>", self.toggle_transmit)
        self.root.bind("<KeyPress-space>", self.start_transmit)
        self.root.bind("<KeyRelease-space>", self.stop_transmit)
        
        # Mode selection
        mode_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        mode_frame.pack(fill=tk.X, pady=10)
        
        self.mode_var = tk.StringVar(value="join")
        
        # Mode buttons
        self.join_btn = tk.Button(mode_frame, text="JOIN ORB", 
                                command=lambda: self.set_mode("join"),
                                font=self.custom_font,
                                bg=self.ACCENT_COLOR if self.mode_var.get() == "join" else self.SECONDARY_COLOR,
                                fg=self.FG_COLOR, bd=0,
                                activebackground=self.ACCENT_COLOR,
                                activeforeground=self.FG_COLOR)
        self.join_btn.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        self.host_btn = tk.Button(mode_frame, text="HOST ORB", 
                                command=lambda: self.set_mode("host"),
                                font=self.custom_font,
                                bg=self.ACCENT_COLOR if self.mode_var.get() == "host" else self.SECONDARY_COLOR,
                                fg=self.FG_COLOR, bd=0,
                                activebackground=self.ACCENT_COLOR,
                                activeforeground=self.FG_COLOR)
        self.host_btn.pack(side=tk.LEFT, expand=True, fill=tk.X)
        
        # Host IP display
        self.host_ip_display = tk.Label(mode_frame, textvariable=self.host_ip_var, 
                                      font=("Courier", 10), bg=self.BG_COLOR, 
                                      fg=self.ACCENT_COLOR)
        self.host_ip_display.pack(fill=tk.X, pady=5)
        
        # Host name display (for clients)
        self.host_name_display = tk.Label(mode_frame, textvariable=self.host_name_var,
                                        font=("Courier", 10), bg=self.BG_COLOR,
                                        fg=self.ACCENT_COLOR)
        self.host_name_display.pack(fill=tk.X, pady=5)
        
        # Connection details
        detail_frame = tk.LabelFrame(main_frame, text=" CONNECTION DETAILS ", 
                                   font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                   fg=self.FG_COLOR, labelanchor='n')
        detail_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(detail_frame, text="ORB Address:", bg=self.BG_COLOR, 
                fg=self.FG_COLOR).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = tk.Entry(detail_frame, font=self.custom_font, 
                                 bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                 insertbackground=self.FG_COLOR, bd=0)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.host_entry.insert(0, "127.0.0.1")
        
        tk.Label(detail_frame, text="Port:", bg=self.BG_COLOR, 
                fg=self.FG_COLOR).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(detail_frame, font=self.custom_font,
                                 bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                 insertbackground=self.FG_COLOR, bd=0)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.port_entry.insert(0, "12345")
        
        # Host name entry (only visible in host mode)
        self.host_name_label = tk.Label(detail_frame, text="Host Name:", bg=self.BG_COLOR,
                                      fg=self.FG_COLOR)
        self.host_name_entry = tk.Entry(detail_frame, font=self.custom_font,
                                      bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                      insertbackground=self.FG_COLOR, bd=0,
                                      textvariable=self.client_name_var)
        
        # Client name entry (only visible in join mode)
        self.client_name_label = tk.Label(detail_frame, text="Your Name:", bg=self.BG_COLOR,
                                        fg=self.FG_COLOR)
        self.client_name_entry = tk.Entry(detail_frame, font=self.custom_font,
                                        bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                        insertbackground=self.FG_COLOR, bd=0,
                                        textvariable=self.client_name_var)
        
        # Device selection
        dev_frame = tk.LabelFrame(main_frame, text=" AUDIO CONFIGURATION ", 
                                font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                fg=self.FG_COLOR, labelanchor='n')
        dev_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(dev_frame, text="Input Device:", bg=self.BG_COLOR,
                fg=self.FG_COLOR).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_dev_combo = ttk.Combobox(dev_frame, state="readonly", 
                                          font=self.custom_font)
        self.input_dev_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        tk.Label(dev_frame, text="Output Device:", bg=self.BG_COLOR,
                fg=self.FG_COLOR).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_dev_combo = ttk.Combobox(dev_frame, state="readonly", 
                                           font=self.custom_font)
        self.output_dev_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Test button
        test_frame = tk.Frame(dev_frame, bg=self.BG_COLOR)
        test_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.test_btn = tk.Button(test_frame, text="TEST AUDIO", 
                                command=self.test_audio_devices,
                                font=self.custom_font, bd=0,
                                bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                activebackground=self.ACCENT_COLOR,
                                activeforeground=self.FG_COLOR)
        self.test_btn.pack(fill=tk.X)
        
        # Encryption toggle
        self.encryption_btn = tk.Button(test_frame, text="TOGGLE ENCRYPTION", 
                                      command=self.toggle_encryption,
                                      font=self.custom_font, bd=0,
                                      bg=self.ENCRYPTION_COLOR, fg=self.FG_COLOR,
                                      activebackground=self.ENCRYPTION_COLOR,
                                      activeforeground=self.FG_COLOR)
        self.encryption_btn.pack(fill=tk.X, pady=(5, 0))
        
        # Control buttons
        btn_frame = tk.Frame(main_frame, bg=self.BG_COLOR)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.connect_btn = tk.Button(btn_frame, text="CONNECT", 
                                   command=self.toggle_connection,
                                   font=self.custom_font, bd=0,
                                   bg=self.ACCENT_COLOR, fg=self.FG_COLOR,
                                   activebackground=self.ACCENT_COLOR,
                                   activeforeground=self.FG_COLOR,
                                   height=2)
        self.connect_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        self.transmit_btn = tk.Button(btn_frame, text="TRANSMIT (SPACE)", 
                                    command=self.toggle_transmit, 
                                    state=tk.DISABLED,
                                    font=self.custom_font, bd=0,
                                    bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                    activebackground=self.TRANSMIT_COLOR,
                                    activeforeground=self.FG_COLOR,
                                    height=2)
        self.transmit_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # Participants list
        part_frame = tk.LabelFrame(main_frame, text=" PARTICIPANTS ", 
                                 font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                 fg=self.FG_COLOR, labelanchor='n')
        part_frame.pack(expand=True, fill=tk.BOTH, pady=10)
        
        self.participants_list = tk.Listbox(part_frame, font=self.custom_font,
                                          bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                          selectbackground=self.ACCENT_COLOR,
                                          selectforeground=self.FG_COLOR,
                                          bd=0, highlightthickness=0)
        self.participants_list.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        # Status bar
        status_bar = tk.Label(main_frame, textvariable=self.status_var,
                            font=("Courier", 10), bd=0, relief=tk.SUNKEN,
                            anchor=tk.W, bg=self.SECONDARY_COLOR,
                            fg=self.FG_COLOR)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Initialize UI
        self.update_ui_mode()
    
    def start_transmit(self, event=None):
        """Start transmitting when spacebar is pressed"""
        if self.running and not self.transmitting:
            self.transmitting = True
            self.space_pressed = True
            self.transmit_btn.config(text="TRANSMITTING (SPACE)", bg=self.TRANSMIT_COLOR)
            self.status_var.set("STATUS: Transmitting")
            self.send_thread = threading.Thread(target=self.send_loop, daemon=True)
            self.send_thread.start()
            self.log("Started transmitting (spacebar)")
    
    def stop_transmit(self, event=None):
        """Stop transmitting when spacebar is released"""
        if self.running and self.space_pressed:
            self.transmitting = False
            self.space_pressed = False
            self.transmit_btn.config(text="TRANSMIT (SPACE)", bg=self.SECONDARY_COLOR)
            self.status_var.set("STATUS: Connected")
            self.log("Stopped transmitting (spacebar)")
    
    def toggle_transmit(self, event=None):
        """Toggle transmit mode (for button click)"""
        if not self.running:
            return
            
        if self.space_pressed:
            return  # Ignore if spacebar is active
            
        self.transmitting = not self.transmitting
        if self.transmitting:
            self.transmit_btn.config(text="TRANSMITTING (SPACE)", bg=self.TRANSMIT_COLOR)
            self.status_var.set("STATUS: Transmitting")
            self.send_thread = threading.Thread(target=self.send_loop, daemon=True)
            self.send_thread.start()
            self.log("Started transmitting (button)")
        else:
            self.transmit_btn.config(text="TRANSMIT (SPACE)", bg=self.SECONDARY_COLOR)
            self.status_var.set("STATUS: Connected")
            self.log("Stopped transmitting (button)")
    
    def toggle_encryption(self):
        """Toggle encryption on/off with visual feedback"""
        self.encryption_enabled = not self.encryption_enabled
        if self.encryption_enabled:
            self.encryption_indicator.config(text="🔒", fg=self.ENCRYPTION_COLOR)
            self.encryption_btn.config(bg=self.ENCRYPTION_COLOR)
            self.log("Encryption enabled")
        else:
            self.encryption_indicator.config(text="⚠️", fg=self.ERROR_COLOR)
            self.encryption_btn.config(bg=self.DISABLED_COLOR)
            self.log("Encryption disabled - WARNING: Communications are not secure!")
    
    def set_mode(self, mode):
        """Set host/join mode and update UI accordingly"""
        self.mode_var.set(mode)
        self.update_ui_mode()
        self.log(f"Mode set to: {mode}")
        
    def update_ui_mode(self):
        """Update UI elements based on current mode"""
        if self.mode_var.get() == "host":
            self.host_entry.config(state=tk.DISABLED)
            self.host_ip_var.set(f"HOST IP: {self.get_local_ip()}")
            self.host_name_var.set(f"HOST NAME: {self.client_name_var.get()}")
            
            # Show host name field, hide client name field
            self.client_name_label.grid_remove()
            self.client_name_entry.grid_remove()
            self.host_name_label.grid(row=2, column=0, sticky=tk.W, pady=5)
            self.host_name_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
            
            # Update button colors
            self.host_btn.config(bg=self.ACCENT_COLOR)
            self.join_btn.config(bg=self.SECONDARY_COLOR)
        else:
            self.host_entry.config(state=tk.NORMAL)
            self.host_ip_var.set("")
            self.host_name_var.set("")
            
            # Show client name field, hide host name field
            self.host_name_label.grid_remove()
            self.host_name_entry.grid_remove()
            self.client_name_label.grid(row=2, column=0, sticky=tk.W, pady=5)
            self.client_name_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
            
            # Update button colors
            self.join_btn.config(bg=self.ACCENT_COLOR)
            self.host_btn.config(bg=self.SECONDARY_COLOR)
    
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
    
    def perform_key_exchange(self, addr, is_host):
        """Perform post-quantum key exchange with a peer"""
        try:
            if is_host:
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
            else:
                # Client receives public key from host
                ready = select.select([self.socket], [], [], 5.0)
                if not ready[0]:
                    raise TimeoutError("Key exchange timeout")
                
                data, _ = self.socket.recvfrom(1024)
                if not data.startswith(b'ORB_KEY_EXCHANGE'):
                    raise ValueError("Invalid key exchange initiation")
                
                # Extract public key
                public_key = data[len('ORB_KEY_EXCHANGE'):]
                
                # Generate encapsulated key and shared secret
                encapsulated_key, shared_secret = encrypt(public_key)
                
                # Send encapsulated key to host
                self.socket.sendto(b'ORB_ENCAPSULATED' + encapsulated_key, addr)
                
                # Derive AES key from shared secret
                aes_key = hashlib.sha256(shared_secret).digest()
                
                # Store the session key
                self.client_key = {
                    'aes_key': aes_key,
                    'last_used': time.time()
                }
                
                self.log("Key exchange completed with host")
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
            
            if self.host_mode:
                # Rotate keys for all connected clients
                for addr in list(self.session_keys.keys()):
                    try:
                        new_key = self.perform_key_exchange(addr, is_host=True)
                        self.session_keys[addr]['aes_key'] = new_key
                        self.session_keys[addr]['last_used'] = current_time
                    except Exception as e:
                        self.log(f"Failed to rotate key for {addr}: {str(e)}", 'warning')
                        del self.session_keys[addr]
            else:
                # Rotate key with host
                if self.client_key:
                    try:
                        new_key = self.perform_key_exchange((self.host_entry.get(), int(self.port_entry.get())), is_host=False)
                        self.client_key['aes_key'] = new_key
                        self.client_key['last_used'] = current_time
                    except Exception as e:
                        self.log(f"Failed to rotate key with host: {str(e)}", 'warning')
                        self.client_key = None
            
            self.last_key_rotation = current_time
    
    def get_orb_art(self):
        return r"""
          _____
        /       \
       /    _    \
      |   / \    |
      |  |   |   |
      |   \_/    |
       \         /
        \  ___  /
         \_____/
        """
    
    def generate_orb_name(self):
        adjectives = ["Eldritch", "Phantom", "Wraith", "Specter", "Haunted", "Cursed"]
        nouns = ["Chamber", "Void", "Abyss", "Crypt", "Shroud", "Wraith"]
        return f"{random.choice(adjectives)}-{random.choice(nouns)}"
    
    def generate_participant_name(self, ip):
        if ip not in self.participant_names:
            first = ["Shadow", "Ghost", "Phantom", "Wraith", "Specter", "Banshee"]
            last = ["Whisper", "Moan", "Howl", "Shriek", "Echo", "Wail"]
            self.participant_names[ip] = f"{random.choice(first)}-{random.choice(last)}-{random.randint(100,999)}"
        return self.participant_names[ip]
    
    def refresh_devices(self):
        try:
            input_devices = []
            output_devices = []
            
            for i in range(self.pyaudio.get_device_count()):
                try:
                    dev = self.pyaudio.get_device_info_by_index(i)
                    # Only show enabled devices (hostApi = 0 is usually the default API)
                    if dev['maxInputChannels'] > 0 and dev['hostApi'] == 0:
                        input_devices.append((i, dev['name']))
                    if dev['maxOutputChannels'] > 0 and dev['hostApi'] == 0:
                        output_devices.append((i, dev['name']))
                except Exception as e:
                    self.log(f"Error checking device {i}: {str(e)}", 'error')
            
            # Update combo boxes
            self.input_dev_combo['values'] = [f"{idx}: {name}" for idx, name in input_devices]
            self.output_dev_combo['values'] = [f"{idx}: {name}" for idx, name in output_devices]
            
            # Select default devices
            try:
                default_input = self.pyaudio.get_default_input_device_info()
                default_output = self.pyaudio.get_default_output_device_info()
                
                if input_devices:
                    try:
                        idx = next(i for i, (idx, name) in enumerate(input_devices) 
                                 if idx == default_input['index'])
                        self.input_dev_combo.current(idx)
                        self.selected_input_idx = input_devices[idx][0]
                    except:
                        self.input_dev_combo.current(0)
                        self.selected_input_idx = input_devices[0][0] if input_devices else 0
                
                if output_devices:
                    try:
                        idx = next(i for i, (idx, name) in enumerate(output_devices) 
                                 if idx == default_output['index'])
                        self.output_dev_combo.current(idx)
                        self.selected_output_idx = output_devices[idx][0]
                    except:
                        self.output_dev_combo.current(0)
                        self.selected_output_idx = output_devices[0][0] if output_devices else 0
            except Exception as e:
                self.log(f"Error setting default devices: {str(e)}", 'error')
                
        except Exception as e:
            self.log(f"Error refreshing devices: {str(e)}", 'error')
            messagebox.showerror("Device Error", f"Could not refresh audio devices:\n{str(e)}")
    
    def test_audio_devices(self):
        """Test the selected audio devices by playing a test sound"""
        try:
            # Get selected devices
            input_idx = int(self.input_dev_combo.get().split(":")[0])
            output_idx = int(self.output_dev_combo.get().split(":")[0])
            
            # Play a test sound
            p = pyaudio.PyAudio()
            stream = p.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=44100,
                output=True,
                output_device_index=output_idx,
                frames_per_buffer=1024
            )
            
            # Generate a simple sine wave
            import math
            samples = []
            for i in range(0, 44100):
                sample = math.sin(2 * math.pi * 440 * i / 44100)
                samples.append(int(sample * 32767))
            
            # Convert to bytes
            import struct
            data = struct.pack('<' + ('h' * len(samples)), *samples)
            
            # Play the sound
            stream.write(data)
            stream.stop_stream()
            stream.close()
            p.terminate()
            
            messagebox.showinfo("Test Audio", "You should hear a 440Hz tone (A4)")
            self.log("Audio test completed successfully")
            
        except Exception as e:
            messagebox.showerror("Test Failed", f"Could not play test sound:\n{str(e)}")
            self.log(f"Audio test failed: {str(e)}", 'error')
    
    def lock_ui(self, locked=True):
        state = tk.DISABLED if locked else tk.NORMAL
        
        # Lock mode selection
        self.join_btn.config(state=state)
        self.host_btn.config(state=state)
        
        # Lock connection details
        self.host_entry.config(state=tk.DISABLED if locked else tk.NORMAL if self.mode_var.get() == "join" else tk.DISABLED)
        self.port_entry.config(state=state)
        
        # Lock name fields based on mode
        if self.mode_var.get() == "host":
            self.host_name_entry.config(state=state)
        else:
            self.client_name_entry.config(state=state)
        
        # Lock device selection
        self.input_dev_combo.config(state="readonly" if not locked else "disabled")
        self.output_dev_combo.config(state="readonly" if not locked else "disabled")
        self.test_btn.config(state=state)
        self.encryption_btn.config(state=state)
    
    def toggle_connection(self):
        if self.running:
            self.stop_connection()
        else:
            self.start_connection()
    
    def verify_connection(self, host, port):
        """Verify that the host is actually running an ORB server"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_socket.settimeout(2)
            
            # Send verification packet
            test_socket.sendto(b'ORB_VERIFY', (host, port))
            
            # Wait for response
            test_socket.settimeout(2)
            data, addr = test_socket.recvfrom(1024)
            
            if data == b'ORB_ACK':
                return True
            return False
        except:
            return False
        finally:
            test_socket.close()
    
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
    
    def start_connection(self):
        try:
            port = int(self.port_entry.get())
            self.host_mode = self.mode_var.get() == "host"
            
            # Get selected devices
            self.selected_input_idx = int(self.input_dev_combo.get().split(":")[0])
            self.selected_output_idx = int(self.output_dev_combo.get().split(":")[0])
            
            # Store the appropriate name
            if self.host_mode:
                self.host_name = self.client_name_var.get()
            else:
                self.client_name = self.client_name_var.get()
            
            # Setup socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if self.host_mode:
                try:
                    self.socket.bind(('0.0.0.0', port))
                    # Start NAT traversal help in background
                    threading.Thread(target=self.help_nat_traversal, args=(port,), daemon=True).start()
                    
                    # Show both public and local IP if available
                    public_ip = self.get_public_ip()
                    if public_ip:
                        self.host_ip_var.set(f"HOST IP (Public): {public_ip}\nHOST IP (Local): {self.get_local_ip()}")
                    else:
                        self.host_ip_var.set(f"HOST IP: {self.get_local_ip()}\n(Public IP detection failed)")
                    
                    self.status_var.set(f"ORB ONLINE: {self.host_name}")
                    self.status_indicator.config(fg=self.RECEIVE_COLOR)
                    self.log(f"Hosting ORB '{self.host_name}' on port {port}")
                    
                    # Generate host key pair
                    if self.encryption_enabled:
                        self.host_public_key, self.host_private_key = self.generate_kyber_keys()
                except Exception as e:
                    raise ConnectionError(f"Failed to bind to port {port}: {str(e)}")
            else:
                host = self.host_entry.get()
                if host in ['localhost', '127.0.0.1', self.get_local_ip()]:
                    host = '127.0.0.1'
                
                # Verify connection before proceeding
                self.status_var.set(f"VERIFYING CONNECTION TO: {host}:{port}")
                self.root.update()
                
                if not self.verify_connection(host, port):
                    raise ConnectionError(f"No ORB server found at {host}:{port}")
                
                self.socket.connect((host, port))
                self.status_var.set(f"CONNECTED TO: {host}:{port}")
                self.status_indicator.config(fg=self.RECEIVE_COLOR)
                self.log(f"Connected to {host}:{port} as '{self.client_name}'")
                
                # Perform key exchange if encryption is enabled
                if self.encryption_enabled:
                    self.perform_key_exchange((host, port), is_host=False)
            
            # Start audio streams
            self.input_stream = self.pyaudio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=44100,
                input=True,
                input_device_index=self.selected_input_idx,
                frames_per_buffer=1024*4,
                start=False
            )
            
            self.output_stream = self.pyaudio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=44100,
                output=True,
                output_device_index=self.selected_output_idx,
                frames_per_buffer=1024*4,
                start=False
            )
            
            self.running = True
            self.connect_btn.config(text="DISCONNECT")
            self.transmit_btn.config(state=tk.NORMAL, bg=self.SECONDARY_COLOR)
            
            # Lock UI
            self.lock_ui(True)
            
            # Start audio streams
            self.input_stream.start_stream()
            self.output_stream.start_stream()
            
            # Start network threads
            self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.receive_thread.start()
            
            self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
            self.update_thread.start()
            
            self.log("Connection established successfully")
            
        except Exception as e:
            self.status_indicator.config(fg=self.ERROR_COLOR)
            error_msg = str(e)
            self.log(f"Connection error: {error_msg}", 'error')
            messagebox.showerror("CONNECTION ERROR", error_msg)
            self.stop_connection()
    
    def stop_connection(self):
        self.log("Stopping connection...")
        self.running = False
        self.transmitting = False
        self.space_pressed = False
        
        try:
            if self.socket:
                self.socket.close()
                self.log("Socket closed")
        except Exception as e:
            self.log(f"Error closing socket: {str(e)}", 'error')
        
        try:
            if self.input_stream:
                self.input_stream.stop_stream()
                self.input_stream.close()
                self.log("Input stream closed")
        except Exception as e:
            self.log(f"Error closing input stream: {str(e)}", 'error')
            
        try:
            if self.output_stream:
                self.output_stream.stop_stream()
                self.output_stream.close()
                self.log("Output stream closed")
        except Exception as e:
            self.log(f"Error closing output stream: {str(e)}", 'error')
        
        # Clear encryption state
        self.session_keys.clear()
        self.client_key = None
        
        self.connect_btn.config(text="CONNECT")
        self.transmit_btn.config(state=tk.DISABLED, bg=self.SECONDARY_COLOR)
        self.status_var.set("ORB: Ready")
        self.status_indicator.config(fg="#666666")
        self.orb_label.config(fg=self.IDLE_COLOR)
        self.participants_list.delete(0, tk.END)
        self.connections.clear()
        self.participant_names.clear()
        
        # Unlock UI
        self.lock_ui(False)
        self.log("Connection fully stopped")
    
    def receive_loop(self):
        self.log("Receive loop started")
        while self.running:
            try:
                ready = select.select([self.socket], [], [], 0.1)
                if ready[0]:
                    data, addr = self.socket.recvfrom(1024*8)
                    
                    # Handle verification requests
                    if data == b'ORB_VERIFY':
                        if self.host_mode:
                            self.socket.sendto(b'ORB_ACK', addr)
                        continue
                    
                    # Handle key exchange initiation from host
                    if data.startswith(b'ORB_KEY_EXCHANGE') and not self.host_mode and self.encryption_enabled:
                        try:
                            # Extract public key and perform key exchange
                            public_key = data[len('ORB_KEY_EXCHANGE'):]
                            
                            # Generate encapsulated key and shared secret
                            encapsulated_key, shared_secret = encrypt(public_key)
                            
                            # Send encapsulated key to host
                            self.socket.sendto(b'ORB_ENCAPSULATED' + encapsulated_key, addr)
                            
                            # Derive AES key from shared secret
                            aes_key = hashlib.sha256(shared_secret).digest()
                            
                            # Store the session key
                            self.client_key = {
                                'aes_key': aes_key,
                                'last_used': time.time()
                            }
                            
                            self.log("Key exchange completed with host")
                        except Exception as e:
                            self.log(f"Key exchange failed: {str(e)}", 'error')
                        continue
                    
                    # Handle encapsulated key from client (host mode)
                    if data.startswith(b'ORB_ENCAPSULATED') and self.host_mode and self.encryption_enabled:
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
                            if self.host_mode:
                                if addr in self.session_keys:
                                    decrypted_data = self.decrypt_audio_data(data, self.session_keys[addr]['aes_key'])
                                    self.session_keys[addr]['last_used'] = time.time()
                                else:
                                    # New client - initiate key exchange
                                    self.perform_key_exchange(addr, is_host=True)
                                    continue
                            else:
                                if self.client_key:
                                    decrypted_data = self.decrypt_audio_data(data, self.client_key['aes_key'])
                                    self.client_key['last_used'] = time.time()
                        except Exception as e:
                            self.log(f"Decryption failed: {str(e)}", 'warning')
                            continue
                    
                    if self.host_mode:
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
                        
                        # Track connections
                        if not any(c[0] == addr for c in self.connections):
                            self.connections.append((addr, None))
                            self.log(f"New connection from {addr}")
                            
                            # If encryption is enabled, perform key exchange
                            if self.encryption_enabled:
                                self.perform_key_exchange(addr, is_host=True)
                    
                    # Play audio
                    try:
                        self.output_stream.write(decrypted_data)
                        self.last_activity = time.time()
                        self.activity_history.append(("receive", time.time()))
                    except Exception as e:
                        self.log(f"Error playing audio: {str(e)}", 'error')
                    
            except (socket.timeout, BlockingIOError):
                continue
            except OSError as e:
                if self.running:
                    self.log(f"Socket error in receive loop: {str(e)}", 'error')
                break
            except Exception as e:
                if self.running:
                    self.log(f"Unexpected error in receive loop: {str(e)}", 'error')
                    raise
    
    def send_loop(self):
        self.log("Send loop started")
        while self.running and self.transmitting:
            try:
                data = self.input_stream.read(1024, exception_on_overflow=False)
                
                # Encrypt data if encryption is enabled
                encrypted_data = data
                if self.encryption_enabled:
                    try:
                        if self.host_mode:
                            # For host, we'll encrypt separately for each client
                            pass
                        else:
                            if self.client_key:
                                encrypted_data = self.encrypt_audio_data(data, self.client_key['aes_key'])
                                self.client_key['last_used'] = time.time()
                    except Exception as e:
                        self.log(f"Encryption failed: {str(e)}", 'warning')
                        continue
                
                if self.host_mode:
                    for addr_info in self.connections:
                        addr = addr_info[0]
                        try:
                            # Encrypt separately for each client if encryption is enabled
                            if self.encryption_enabled and addr in self.session_keys:
                                client_encrypted_data = self.encrypt_audio_data(data, self.session_keys[addr]['aes_key'])
                                self.socket.sendto(client_encrypted_data, addr)
                            else:
                                self.socket.sendto(data, addr)
                        except Exception as e:
                            self.log(f"Error sending to {addr}: {str(e)}", 'error')
                            self.connections.remove(addr_info)
                else:
                    try:
                        self.socket.send(encrypted_data if self.encryption_enabled else data)
                    except Exception as e:
                        self.log(f"Error sending to host: {str(e)}", 'error')
                        self.stop_connection()
                        break
                
                self.last_activity = time.time()
                self.activity_history.append(("send", time.time()))
                
                # Rotate keys if needed
                self.rotate_keys_if_needed()
                
            except (socket.timeout, BlockingIOError):
                continue
            except OSError as e:
                if self.running and self.transmitting:
                    self.log(f"Socket error in send loop: {str(e)}", 'error')
                break
            except Exception as e:
                if self.running and self.transmitting:
                    self.log(f"Unexpected error in send loop: {str(e)}", 'error')
                    raise
    
    def update_loop(self):
        self.log("Update loop started")
        while self.running:
            try:
                # Update participant list
                self.participants_list.delete(0, tk.END)
                
                if self.host_mode:
                    # Show host name at top
                    self.participants_list.insert(tk.END, f"Host: {self.host_name}")
                    
                    # List all connected clients
                    for addr, _ in self.connections:
                        name = self.generate_participant_name(addr[0])
                        self.participants_list.insert(tk.END, f"  → {name} @ {addr[0]}")
                else:
                    # Show host name if available
                    if self.host_name_var.get():
                        self.participants_list.insert(tk.END, f"Connected to: {self.host_name_var.get()}")
                    else:
                        self.participants_list.insert(tk.END, "Connected to ORB")
                    
                    # Show client's own name
                    self.participants_list.insert(tk.END, f"You: {self.client_name}")
                
                # Update orb color based on activity
                now = time.time()
                last_send = max((t for typ, t in self.activity_history if typ == "send"), default=0)
                last_receive = max((t for typ, t in self.activity_history if typ == "receive"), default=0)
                
                if self.transmitting:
                    self.orb_label.config(fg=self.TRANSMIT_COLOR)
                elif now - last_receive < 0.3:  # Recently received audio
                    self.orb_label.config(fg=self.RECEIVE_COLOR)
                else:
                    self.orb_label.config(fg=self.IDLE_COLOR)
                
                time.sleep(0.1)
            except Exception as e:
                self.log(f"Error in update loop: {str(e)}", 'error')
                if self.running:
                    raise
    
    def on_close(self):
        self.log("Application closing...")
        self.running = False
        if hasattr(self, 'receive_thread'):
            self.receive_thread.join(0.1)
        if hasattr(self, 'update_thread'):
            self.update_thread.join(0.1)
        if hasattr(self, 'send_thread'):
            self.send_thread.join(0.1)
        self.stop_connection()
        self.root.destroy()
        self.log("Application closed")

if __name__ == "__main__":
    root = tk.Tk()
    app = OrbApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()