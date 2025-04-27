import json
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
from quantcrypt.kem import MLKEM_1024
import hashlib
import struct
from PIL import Image, ImageTk, ImageOps
import numpy as np
import argparse

class ORBv3:
    def __init__(self, root):
        self.root = root
        self.root.title("ORB v3 (PQ-Encrypted)")
        self.root.geometry("600x1000")
        self.root.minsize(600, 800)
        
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
        
        # Application state
        self.is_host = False
        self.running = False
        self.transmitting = False
        self.space_pressed = False
        self.encryption_enabled = True
        self.show_log = False
        
        # Participant tracking
        self.participants = {}  # {address: name}
        self.host_address = None
        self.host_name = ""
        self.client_name = ""
        self.avatar_data = {}  # {address: avatar_data}
        self.avatars = {}
        
        # Encryption state
        self.session_keys = {}  # For host mode
        self.client_key = None  # For client mode
        self.key_rotation_interval = 60
        self.last_key_rotation = 0
        
        # Initialize KEM
        self.kem = MLKEM_1024()
        
        # Audio setup
        self.pyaudio = pyaudio.PyAudio()
        self.input_stream = None
        self.output_stream = None
        self.selected_input_idx = 0
        self.selected_output_idx = 0
        
        # Network setup
        self.socket = None
        self.port = 12345
        self.connections = []
        
        # Transmission state
        self.last_activity = 0
        self.activity_history = deque(maxlen=10)
        
        # Password for host mode
        self.password = self.generate_password()
        
        # Configure logging
        self.setup_logging()
        
        # UI variables
        self.status_var = tk.StringVar()
        self.status_var.set("ORB: Ready")
        self.host_ip_var = tk.StringVar()
        self.host_ip_var.set("")
        self.host_name_var = tk.StringVar()
        self.host_name_var.set("")
        self.client_name_var = tk.StringVar()
        self.client_name_var.set(self.generate_orb_name())
        self.password_var = tk.StringVar()
        self.password_var.set(self.password)
        
        # Setup UI
        self.setup_ui()
        self.refresh_devices()
        
        # Generate host key pair if encryption is enabled
        if self.encryption_enabled:
            self.host_public_key, self.host_secret_key = self.generate_mlkem_keys()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='orb_v3.log',
            filemode='w'
        )
        self.logger = logging.getLogger('ORBv3')
        
    def log(self, message, level='info'):
        getattr(self.logger, level)(message)
        print(f"[{level.upper()}] {message}")
        if hasattr(self, 'log_text') and self.show_log:
            self.log_text.insert(tk.END, f"[{level.upper()}] {message}\n")
            self.log_text.see(tk.END)
        
    def setup_ui(self):
        # Create main container with scrollbar
        self.main_frame = tk.Frame(self.root, bg=self.BG_COLOR)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a canvas for scrolling
        self.canvas = tk.Canvas(self.main_frame, bg=self.BG_COLOR, highlightthickness=0)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Setup ttk styles for dark scrollbar
        self.setup_ttk_styles()
        
        # Add scrollbar
        self.scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, 
                                     command=self.canvas.yview, style="Vertical.TScrollbar")
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure the canvas
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig("content", width=e.width))

        # Create another frame inside the canvas
        self.content_frame = tk.Frame(self.canvas, bg=self.BG_COLOR)
        self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw", tags="content")
        
        # Update scroll region to fit content
        self.content_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        
        # Bind mousewheel for scrolling
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Custom font
        self.custom_font = font.Font(family="Helvetica", size=12)
        self.title_font = font.Font(family="Helvetica", size=18, weight="bold")
        
        # Header
        header_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(header_frame, text="ORB v3", font=self.title_font, 
                bg=self.BG_COLOR, fg=self.FG_COLOR).pack(side=tk.LEFT)
        
        # Mode toggle button
        self.mode_btn = tk.Button(header_frame, text="CLIENT MODE", 
                                 command=self.toggle_mode,
                                 font=self.custom_font, bd=0,
                                 bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                 activebackground=self.ACCENT_COLOR,
                                 activeforeground=self.FG_COLOR)
        self.mode_btn.pack(side=tk.LEFT, padx=10)
        
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
        self.orb_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        self.orb_frame.pack(pady=20)
        
        self.orb_label = tk.Label(self.orb_frame, text=self.get_orb_art(), 
                                font=("Courier", 5), fg=self.IDLE_COLOR,
                                bg=self.BG_COLOR)
        self.orb_label.pack()
        
        # Host mode UI elements
        self.setup_host_ui()
        
        # Client mode UI elements
        self.setup_client_ui()
        
        # Initially show client UI
        self.show_client_ui()
        
        # Status bar
        status_bar = tk.Label(self.content_frame, textvariable=self.status_var,
                            font=("Courier", 10), bd=0, relief=tk.SUNKEN,
                            anchor=tk.W, bg=self.SECONDARY_COLOR,
                            fg=self.FG_COLOR)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Bind orb click
        self.orb_label.bind("<Button-1>", self.toggle_transmit)
        self.root.bind("<KeyPress-space>", self.start_transmit)
        self.root.bind("<KeyRelease-space>", self.stop_transmit)
    
    def setup_host_ui(self):
        """Setup UI elements specific to host mode"""
        # Host info frame
        self.host_info_frame = tk.LabelFrame(self.content_frame, text=" HOST INFORMATION ", 
                                           font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                           fg=self.FG_COLOR, labelanchor='n')
        self.host_info_frame.pack(fill=tk.X, pady=5, padx=10)
        
        # Port entry
        tk.Label(self.host_info_frame, text="Port:", bg=self.BG_COLOR, 
                fg=self.FG_COLOR).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(self.host_info_frame, font=self.custom_font,
                                 bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                 insertbackground=self.FG_COLOR, bd=0)
        self.port_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.port_entry.insert(0, str(self.port))
        
        # Host name entry
        tk.Label(self.host_info_frame, text="Host Name:", bg=self.BG_COLOR,
                fg=self.FG_COLOR).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.host_name_entry = tk.Entry(self.host_info_frame, font=self.custom_font,
                                      bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                      insertbackground=self.FG_COLOR, bd=0)
        self.host_name_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.host_name_entry.insert(0, self.generate_orb_name())
        
        # Password entry
        tk.Label(self.host_info_frame, text="Password:", bg=self.BG_COLOR,
                fg=self.FG_COLOR).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_entry = tk.Entry(self.host_info_frame, font=self.custom_font,
                                     bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                     insertbackground=self.FG_COLOR, bd=0,
                                     textvariable=self.password_var)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Encryption toggle for host
        self.host_encryption_btn = tk.Button(self.host_info_frame, text="TOGGLE ENCRYPTION", 
                                           command=self.toggle_encryption,
                                           font=self.custom_font, bd=0,
                                           bg=self.ENCRYPTION_COLOR, fg=self.FG_COLOR,
                                           activebackground=self.ENCRYPTION_COLOR,
                                           activeforeground=self.FG_COLOR)
        self.host_encryption_btn.grid(row=3, column=0, columnspan=2, pady=5, sticky=tk.EW)
        
        # Host control buttons
        self.host_btn_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        self.host_btn_frame.pack(fill=tk.X, pady=10, padx=10)
        
        self.start_host_btn = tk.Button(self.host_btn_frame, text="OPEN CHAMBER", 
                                      command=self.start_host,
                                      font=self.custom_font, bd=0,
                                      bg=self.ACCENT_COLOR, fg=self.FG_COLOR,
                                      activebackground=self.ACCENT_COLOR,
                                      activeforeground=self.FG_COLOR,
                                      height=2)
        self.start_host_btn.pack(fill=tk.X, padx=5, pady=5)
        
        self.seal_chamber_btn = tk.Button(self.host_btn_frame, text="SEAL CHAMBER", 
                                        command=self.stop_host,
                                        state=tk.DISABLED,
                                        font=self.custom_font, bd=0,
                                        bg=self.ERROR_COLOR, fg=self.FG_COLOR,
                                        activebackground=self.ERROR_COLOR,
                                        activeforeground=self.FG_COLOR,
                                        height=2)
        self.seal_chamber_btn.pack(fill=tk.X, padx=5, pady=5)
        
        # Chamber View
        self.chamber_frame = tk.LabelFrame(self.content_frame, text=" SPECTRAL CHAMBER ", 
                                         font=(self.custom_font, 10), bg=self.BG_COLOR,
                                         fg=self.FG_COLOR, labelanchor='n')
        self.chamber_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
        
        self.chamber_canvas = tk.Canvas(self.chamber_frame, width=900, height=300, bg='#000010')
        self.chamber_canvas.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)        
        
        # Participants list
        self.participants_frame = tk.LabelFrame(self.content_frame, text=" PARTICIPANTS ", 
                                              font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                              fg=self.FG_COLOR, labelanchor='n')
        self.participants_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
        
        self.participants_list = tk.Listbox(self.participants_frame, font=self.custom_font,
                                          bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                          selectbackground=self.ACCENT_COLOR,
                                          selectforeground=self.FG_COLOR,
                                          bd=0, highlightthickness=0)
        self.participants_list.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        # Log display
        self.log_frame = tk.LabelFrame(self.content_frame, text=" LOG OUTPUT ", 
                                     font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                     fg=self.FG_COLOR, labelanchor='n')
        self.log_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
        
        self.log_text = tk.Text(self.log_frame, font=("Courier", 8), 
                              bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                              wrap=tk.WORD, bd=0, highlightthickness=0)
        self.log_text.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        self.toggle_log_btn = tk.Button(self.log_frame, text="HIDE LOG", 
                                      command=self.toggle_log,
                                      font=self.custom_font, bd=0,
                                      bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                      activebackground=self.ACCENT_COLOR,
                                      activeforeground=self.FG_COLOR)
        self.toggle_log_btn.pack(fill=tk.X, padx=5, pady=5)
    
    def setup_client_ui(self):
        """Setup UI elements specific to client mode"""
        # Connection details
        self.client_detail_frame = tk.LabelFrame(self.content_frame, text=" CONNECTION DETAILS ", 
                                               font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                               fg=self.FG_COLOR, labelanchor='n')
        self.client_detail_frame.pack(fill=tk.X, pady=5, padx=10)
        
        tk.Label(self.client_detail_frame, text="ORB Address:", bg=self.BG_COLOR, 
                fg=self.FG_COLOR).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.host_entry = tk.Entry(self.client_detail_frame, font=self.custom_font, 
                                 bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                 insertbackground=self.FG_COLOR, bd=0)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.host_entry.insert(0, "127.0.0.1")
        
        tk.Label(self.client_detail_frame, text="Port:", bg=self.BG_COLOR, 
                fg=self.FG_COLOR).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.client_port_entry = tk.Entry(self.client_detail_frame, font=self.custom_font,
                                        bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                        insertbackground=self.FG_COLOR, bd=0)
        self.client_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.client_port_entry.insert(0, "12345")
        
        # Client name entry
        self.client_name_label = tk.Label(self.client_detail_frame, text="Your Name:", bg=self.BG_COLOR,
                                        fg=self.FG_COLOR)
        self.client_name_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        self.client_name_entry = tk.Entry(self.client_detail_frame, font=self.custom_font,
                                        bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                        insertbackground=self.FG_COLOR, bd=0,
                                        textvariable=self.client_name_var)
        self.client_name_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Password entry
        self.password_label = tk.Label(self.client_detail_frame, text="Password:", bg=self.BG_COLOR,
                                     fg=self.FG_COLOR)
        self.password_label.grid(row=3, column=0, sticky=tk.W, pady=5)
        self.client_password_entry = tk.Entry(self.client_detail_frame, font=self.custom_font,
                                            bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                            insertbackground=self.FG_COLOR, bd=0,
                                            show="*")
        self.client_password_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Host name display
        self.host_name_display = tk.Label(self.client_detail_frame, textvariable=self.host_name_var,
                                        font=("Courier", 10), bg=self.BG_COLOR,
                                        fg=self.ACCENT_COLOR)
        self.host_name_display.grid(row=4, column=0, columnspan=2, sticky=tk.W)
        
        # Device selection
        self.dev_frame = tk.LabelFrame(self.content_frame, text=" AUDIO CONFIGURATION ", 
                                     font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                     fg=self.FG_COLOR, labelanchor='n')
        self.dev_frame.pack(fill=tk.X, pady=10, padx=10)
        
        tk.Label(self.dev_frame, text="Input Device:", bg=self.BG_COLOR,
                fg=self.FG_COLOR).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.input_dev_combo = ttk.Combobox(self.dev_frame, state="readonly", 
                                          font=self.custom_font)
        self.input_dev_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        tk.Label(self.dev_frame, text="Output Device:", bg=self.BG_COLOR,
                fg=self.FG_COLOR).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.output_dev_combo = ttk.Combobox(self.dev_frame, state="readonly", 
                                           font=self.custom_font)
        self.output_dev_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Test button
        self.test_frame = tk.Frame(self.dev_frame, bg=self.BG_COLOR)
        self.test_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.test_btn = tk.Button(self.test_frame, text="TEST AUDIO", 
                                command=self.test_audio_devices,
                                font=self.custom_font, bd=0,
                                bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                activebackground=self.ACCENT_COLOR,
                                activeforeground=self.FG_COLOR)
        self.test_btn.pack(fill=tk.X)
        
        # Encryption toggle
        self.encryption_btn = tk.Button(self.test_frame, text="TOGGLE ENCRYPTION", 
                                      command=self.toggle_encryption,
                                      font=self.custom_font, bd=0,
                                      bg=self.ENCRYPTION_COLOR, fg=self.FG_COLOR,
                                      activebackground=self.ENCRYPTION_COLOR,
                                      activeforeground=self.FG_COLOR)
        self.encryption_btn.pack(fill=tk.X, pady=(5, 0))
        
        # Control buttons
        self.btn_frame = tk.Frame(self.content_frame, bg=self.BG_COLOR)
        self.btn_frame.pack(fill=tk.X, pady=10, padx=10)
        
        self.connect_btn = tk.Button(self.btn_frame, text="CONNECT", 
                                   command=self.toggle_connection,
                                   font=self.custom_font, bd=0,
                                   bg=self.ACCENT_COLOR, fg=self.FG_COLOR,
                                   activebackground=self.ACCENT_COLOR,
                                   activeforeground=self.FG_COLOR,
                                   height=2)
        self.connect_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        self.transmit_btn = tk.Button(self.btn_frame, text="TRANSMIT (SPACE)", 
                                    command=self.toggle_transmit, 
                                    state=tk.DISABLED,
                                    font=self.custom_font, bd=0,
                                    bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                    activebackground=self.TRANSMIT_COLOR,
                                    activeforeground=self.FG_COLOR,
                                    height=2)
        self.transmit_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        
        # Avatar Creator Frame
        self.creator_frame = tk.LabelFrame(self.content_frame, text="HOLOGRAM APPEARANCE", 
                                         fg="#00ffff", bg=self.BG_COLOR)
        self.creator_frame.pack(pady=10, fill=tk.X, padx=10)
        
        # Body Type
        tk.Label(self.creator_frame, text="Chassis:", fg="white", bg=self.BG_COLOR).grid(row=0, column=0)
        self.body_var = tk.IntVar(value=1)
        self.body_combo = ttk.Combobox(self.creator_frame, values=[1, 2], textvariable=self.body_var,
                                      state="readonly")
        self.body_combo.grid(row=0, column=1)
        self.body_var.trace('w', lambda *args: self.update_preview())
        
        # Garment
        tk.Label(self.creator_frame, text="Vestment:", fg="white", bg=self.BG_COLOR).grid(row=1, column=0)
        self.top_var = tk.IntVar(value=1)
        self.top_combo = ttk.Combobox(self.creator_frame, values=[1, 2, 3], textvariable=self.top_var,
                                     state="readonly")
        self.top_combo.grid(row=1, column=1)
        self.top_var.trace('w', lambda *args: self.update_preview())
        
        # Headwear
        tk.Label(self.creator_frame, text="Cowl:", fg="white", bg=self.BG_COLOR).grid(row=2, column=0)
        self.head_var = tk.IntVar(value=1)
        self.head_combo = ttk.Combobox(self.creator_frame, values=[1, 2, 3], textvariable=self.head_var,
                                      state="readonly")
        self.head_combo.grid(row=2, column=1)
        self.head_var.trace('w', lambda *args: self.update_preview())
        
        # Preview
        self.preview_canvas = tk.Canvas(self.creator_frame, width=200, height=300, bg='#000010')
        self.preview_canvas.grid(row=3, columnspan=2, pady=10)
        self.update_preview()
        
        # Client Chamber View
        self.client_chamber_frame = tk.LabelFrame(self.content_frame, text=" SPECTRAL CHAMBER ", 
                                                font=(self.custom_font, 10), bg=self.BG_COLOR,
                                                fg=self.FG_COLOR, labelanchor='n')
        
        self.client_chamber_canvas = tk.Canvas(self.client_chamber_frame, width=900, height=300, bg='#000010')
        self.client_chamber_canvas.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        # Client Participants list
        self.client_participants_frame = tk.LabelFrame(self.content_frame, text=" PARTICIPANTS ", 
                                                     font=(self.custom_font, 10), bg=self.BG_COLOR, 
                                                     fg=self.FG_COLOR, labelanchor='n')
        
        self.client_participants_list = tk.Listbox(self.client_participants_frame, font=self.custom_font,
                                                 bg=self.SECONDARY_COLOR, fg=self.FG_COLOR,
                                                 selectbackground=self.ACCENT_COLOR,
                                                 selectforeground=self.FG_COLOR,
                                                 bd=0, highlightthickness=0)
        self.client_participants_list.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
    
    def setup_ttk_styles(self):
        style = ttk.Style()
        style.theme_use('clam')  # Gives us most control over styling
        
        # Configure the scrollbar style
        style.configure("Vertical.TScrollbar",
            background=self.SECONDARY_COLOR,
            troughcolor=self.BG_COLOR,
            bordercolor=self.BG_COLOR,
            arrowcolor=self.FG_COLOR,
            lightcolor=self.SECONDARY_COLOR,
            darkcolor=self.FG_COLOR,
            gripcount=0,
            relief='flat'
        )
        
        style.map("Vertical.TScrollbar",
            background=[('active', self.ACCENT_COLOR)],
        )
    
    def get_orb_art(self):
        return r"""
                                ▒▓▓███████▓▒                                      
                              ▒▓█▓▓▓▓▓▓▓▓▓▓▓▓▓▒                                   
                            ▒▓▓▓▒░         ░▒▓▓▓░                                 
                           ░▓▓▓▒               ░▓▒░▓                         
                         ░▓▓▒                ░▓█████▓                             
                      ░░░░▒░                 ▒▓▓▓▒░▓██░                           
                       ░░ ░░                 ▒█▓▒ ░░░██▒                          
                        ░░░░░░         ▒▓▓░  ▒██▒ ▒▒▒▒█▓░                         
                      ░░▓▓▒░░░  ░     ░███▓▓░ ██▓ ▓░█ ██                          
                     ░▒█▒▓▓░░░  ░     ▒█▒▒░▒██▓▓█ ▓░█▒█▓▒░                        
                     ░▒▓░▓▓  ▒░░░     ▓█░▓░ ▒░▒ █░█░█▒█▒ ▒                        
                    ░░▒█ ▓▓░░░░░▒ ░░░░▓█ ▒▓█▒░▒▒▓░█░█░█▒░░                        
                    ░░░█▒▒▓▓▒▒░ ▒░░░░░░█░ ████▒▒░▓███▒▓▒▒░                        
                       ▓█ ░▒▓▓░ ░▒ ░▒▒░████░  ░░▒█ █░█▓▒░░                        
                     ░░░██░ ▒▓▓░ ░░▒▒▓▓▒████░ ░▒█▒█▓▓▓░░                          
                         ██▒ ▒▓█▓███▓▓█████▓░ ░▓▓██▓▓▓▓                           
                          ██░ ░▓▒░       ░▒▒░ ░▒▒▓░▒▓▓▓                           
                         ▒██░░▒▒▓▒█████▒░░▒█▒▒░░ ░ ░██░                           
                   ░░▒███▒░▒▓██░███████████▓ ░░ ░  ▓█▒                            
                  ░▓▒ ▓ ░▒███▓▓██▓░░░▓▓▒░░░░░▒░░░░▒██░                            
                   ▒ ▒▓██▓  ░░░▓██████▒  ░░ ▒▓ ░ ▒██▒                             
                  ░▒▒░▓▒░           ░██▒░░░▒███████░                              
                    ░▒ ░░░       ░░░▒▒▓██▓▓██▒▓██▒░█▓░                            
                     ░▒ ░░   ░░░ ▓█▒▒ ░▓███▓░░████████▒░                          
                    ░▒░░░▒  ░░░▓█▓▓░▓▓▒░  ░▓██████▒░▒███▒                         
                    ▓░▒▒▓▒░░░▓█▓ ▓█░     ░██▓ ████▓▒ ░▓██                         
             ▒░░░░░▒▓█░▒▓ ░█▓░ ▓▓ ▒▒▒  ░▓█▒▓████▓▓██░░░██▓░                       
             ░▓█   ░▓███████▓░▒  ▒██▓▒▒░░▒██▓ ░░░░░█▒░░ ███░                      
            ░▓░████████▒ ▒▓▒██▓░▒█▓▓▓░░▒██▒ ▒░  ░  ██ ░░▒▒█▓                      
              █▓ ░▓█▒░░░ ▒  ▒▒░░░▓███▒▒▒ ░ ░ ░▒░░░░▓▒▓█████▓                      
             ░░████▒  ░▒▓██████▒████▒  ░░▒▓█▓██▓▒▒░█████▓░░                     
                 ▒█▓▒▓███████░░▒░    ░▒████▒ ░░░ ░ ░ ▒▓▒  ░ ░                     
              ░░▒░▒████▒▒▓░ ░ ░░  ░███▓  ▒████████▓░░▓██▓░░ ░    ░                
          ░▒▓█████▓░▒▓▒░▒▒▓▒░ ░▓█▓▒▒ ░▓███▒▒▒▒▒░  ░▒██▓▒▒░░░ ░▒▒█▓▒               
           ▒▒▒▓█▓▓█▓█▓▓░▒░░   ▒▒▒██▓░░███▓▒▒▒█▓▒▒▓▓▒ ▒▒░▒░░ ▒███▓▓▒               
           ▒▒█▓  ░▒  █▓▓░▒▓▒░ █▓▓████████▓░░▒███▓▒▒▒▓█▓▒▓▒  ▒▓▒▒██                
           ░▓█░ ░▒░░▒▓ ░ ▒▓█████▓░   ▒▓▒▒███▓▒░▓▓▓▓▓▓▒  ▒▓▒░░▒▓▓▒░▓██▓
          ░▒█▓  ░░░░▒░░▒▒░░░ ▒████▓▒▒▓▒▒░░░██░░ ░   ░▒░  ▒▒▒▒▒▒░▒▓████      
          ░▓█▒░  ░░░▓███▓▒░░░▓▓▒ ░▒▓█▓░░  ░▒░▓▒▓▒▓▓▒░░    ░░▒▒░░ ░▓███       
           ▒███████████▒░   ░░░▒ ▒▓████████████████████████████▓██████
           ░▒████████████████▓██████▒▒▓███████▓▓▓▓███████████████▓▒░  
        """
    
    def generate_orb_name(self):
        adjectives = ["Eldritch", "Phantom", "Wraith", "Specter", "Haunted", "Cursed", "Arcane", "Occult", "Blasphemous", "Forbidden", "Abyssal", "Malevolent", "Unhallowed", "Nameless", "Forgotten", "Lovecraftian", "Shrouded", "Tenebrous", "Grotesque", "Unfathomable", "Otherworldly", "Revenant", "Dreadful", "Sepulchral", "Sinister", "Chthonic", "Morbid", "Macabre", "Necrotic", "Withered", "Hollow", "Whispering", "Shadowed", "Lurking", "Ghastly", "Obsidian", "Umbral", "Howling", "Cryptic", "Voidbound"]
        nouns = ["Chamber", "Void", "Abyss", "Crypt", "Shroud", "Wraith", "Sanctum", "Ritual", "Monolith", "Relic", "Sigil", "Tomb", "Whisper", "Horror", "Oracle", "Eclipse", "Catacomb", "Entity", "Obelisk", "Revenant", "Seance", "Shrine", "Effigy", "Chasm", "Nightmare", "Specter", "Corruption", "Grimoire", "Idol", "Temple", "Cult", "Decay", "Lament", "Labyrinth", "Flesh", "Scourge", "Coven", "Depths", "Pact", "Unbeing", "Serpent", "Mycelium", "Silhouette", "Darkness", "Curse"]
        return f"{random.choice(adjectives)}-{random.choice(nouns)}"
    
    def generate_password(self):
        adjectives = ["Eldritch", "Phantom", "Wraith", "Specter", "Haunted", "Cursed", "Arcane", "Occult", "Blasphemous", "Forbidden", "Abyssal", "Malevolent", "Unhallowed", "Nameless", "Forgotten", "Lovecraftian", "Shrouded", "Tenebrous", "Grotesque", "Unfathomable"]
        nouns = ["Chamber", "Void", "Abyss", "Crypt", "Shroud", "Wraith", "Sanctum", "Ritual", "Monolith", "Relic", "Sigil", "Tomb", "Whisper", "Horror", "Oracle", "Eclipse", "Catacomb", "Entity", "Obelisk", "Revenant"]
        return f"{random.choice(adjectives)}-{random.choice(nouns)}"
    
    def toggle_mode(self):
        """Toggle between host and client mode"""
        self.is_host = not self.is_host
        
        if self.is_host:
            self.mode_btn.config(text="HOST MODE")
            self.show_host_ui()
        else:
            self.mode_btn.config(text="CLIENT MODE")
            self.show_client_ui()
    
    def show_host_ui(self):
        """Show host mode UI elements"""
        # Hide all client UI elements
        self.client_detail_frame.pack_forget()
        self.dev_frame.pack_forget()
        self.btn_frame.pack_forget()
        self.creator_frame.pack_forget()
        self.client_chamber_frame.pack_forget()
        self.client_participants_frame.pack_forget()
        
        # Show host UI elements
        self.host_info_frame.pack(fill=tk.X, pady=5, padx=10)
        self.host_btn_frame.pack(fill=tk.X, pady=10, padx=10)
        self.chamber_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
        self.participants_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
        self.log_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
    
    def show_client_ui(self):
        """Show client mode UI elements"""
        # Hide all host UI elements
        self.host_info_frame.pack_forget()
        self.host_btn_frame.pack_forget()
        self.chamber_frame.pack_forget()
        self.participants_frame.pack_forget()
        self.log_frame.pack_forget()
        
        # Show client UI elements
        self.client_detail_frame.pack(fill=tk.X, pady=5, padx=10)
        self.dev_frame.pack(fill=tk.X, pady=10, padx=10)
        self.btn_frame.pack(fill=tk.X, pady=10, padx=10)
        self.creator_frame.pack(pady=10, fill=tk.X, padx=10)
        
        # Only show chamber and participants if connected
        if self.running:
            self.client_chamber_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
            self.client_participants_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
    
    def toggle_log(self):
        """Toggle log display visibility"""
        self.show_log = not self.show_log
        if self.show_log:
            self.toggle_log_btn.config(text="HIDE LOG")
            self.log_text.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        else:
            self.toggle_log_btn.config(text="SHOW LOG")
            self.log_text.pack_forget()
    
    def update_preview(self, *args):
        """Update the avatar preview with current selections"""
        self.avatar_data = {
            'body': self.body_var.get(),
            'top': self.top_var.get(),
            'head': self.head_var.get()
        }
        
        img = self.generate_avatar_image(self.avatar_data)
        if img:  # Only update if we got a valid image
            self.preview_canvas.delete("all")
            self.preview_canvas.create_image(100, 150, image=img)
            self.preview_img = img  # Keep reference to prevent garbage collection

    def generate_avatar_image(self, data):
        try:
            # Load chassis-specific assets
            chassis_folder = f"assets/chassis_{data['body']}"
            
            # Load base image
            base = Image.open(f"{chassis_folder}/base.png").convert("RGBA")
            
            # Load vestment if exists
            vestment_path = f"{chassis_folder}/vestment_{data['top']}.png"
            if os.path.exists(vestment_path):
                top = Image.open(vestment_path).convert("RGBA")
                base.alpha_composite(top)
            
            # Load cowl if exists
            cowl_path = f"{chassis_folder}/cowl_{data['head']}.png"
            if os.path.exists(cowl_path):
                head = Image.open(cowl_path).convert("RGBA")
                base.alpha_composite(head)
            
            # Hologram effect
            base = base.convert("RGB")
            base = ImageOps.colorize(base.convert("L"), "#000000", "#00ffff")
            base.putalpha(128)
            
            # Add scanlines
            arr = np.array(base)
            arr[::3, :, 3] = arr[::3, :, 3] * 0.6
            
            return ImageTk.PhotoImage(Image.fromarray(arr))
        except Exception as e:
            self.log(f"Error generating avatar image: {str(e)}", 'error')
            return None
    
    def update_chamber_view(self, avatars):
        """Update the chamber view with participant avatars"""
        canvas = self.chamber_canvas if self.is_host else self.client_chamber_canvas
        canvas.delete("all")
        self.avatar_imgs = []  # Clear previous references to prevent garbage collection

        # Debug logging
        self.log(f"Updating chamber with avatars: {avatars}", 'debug')

        # Convert string addresses back to (ip, port) tuples
        def parse_address(addr_str):
            try:
                ip, port = addr_str.split(':')
                return (ip, int(port))
            except:
                self.log(f"Malformed address string: {addr_str}", 'warning')
                return None

        # Filter out host and self
        other_avatars = {}
        for addr_str, data in avatars.items():
            addr = parse_address(addr_str)
            if not addr:
                continue
                
            # Skip host and self
            if addr == self.host_address or addr == ('127.0.0.1', self.socket.getsockname()[1]):
                continue
                
            other_avatars[addr] = data

        # Debug logging
        self.log(f"Filtered avatars: {other_avatars}", 'debug')

        # Calculate layout parameters
        canvas_width = canvas.winfo_width()
        canvas_height = canvas.winfo_height()
        num_avatars = len(other_avatars)

        # Show message if no other participants
        if num_avatars == 0:
            canvas.create_text(
                canvas_width/2, canvas_height/2,
                text="No other participants in the chamber",
                fill="#00ffff",
                font=("Courier", 14),
                anchor=tk.CENTER
            )
            return

        # Calculate grid layout
        max_cols = 3
        num_rows = (num_avatars + max_cols - 1) // max_cols
        num_cols = min(num_avatars, max_cols)
        
        # Calculate cell dimensions
        cell_width = canvas_width / num_cols
        cell_height = canvas_height / num_rows
        
        # Calculate avatar size (80% of smallest cell dimension)
        avatar_size = min(cell_width, cell_height) * 0.8
        avatar_width = avatar_height = int(avatar_size)

        # Position and draw each avatar
        for i, (addr, data) in enumerate(other_avatars.items()):
            row = i // num_cols
            col = i % num_cols
            
            # Calculate center position
            x = col * cell_width + cell_width / 2
            y = row * cell_height + cell_height / 2
            
            # Generate and place avatar
            try:
                img = self.generate_avatar_image(data)
                if img:
                    # Scale image while maintaining aspect ratio
                    img_width, img_height = ImageTk.getimage(img).size
                    scale = min(avatar_width/img_width, avatar_height/img_height)
                    new_width = int(img_width * scale)
                    new_height = int(img_height * scale)
                    
                    scaled_img = ImageTk.PhotoImage(
                        ImageTk.getimage(img).resize(
                            (new_width, new_height),
                            Image.Resampling.LANCZOS
                        )
                    )
                    
                    canvas.create_image(
                        x, y,
                        image=scaled_img,
                        anchor=tk.CENTER
                    )
                    self.avatar_imgs.append(scaled_img)  # Keep reference
                    
                    # Add participant name below avatar
                    participant_name = self.participants.get(addr, f"Guest-{random.randint(100,999)}")
                    canvas.create_text(
                        x, y + new_height/2 + 15,
                        text=participant_name,
                        fill="#00ffff",
                        font=("Courier", 10)
                    )
            except Exception as e:
                self.log(f"Error displaying avatar for {addr}: {str(e)}", 'error')
    
    def start_transmit(self, event=None):
        """Start transmitting when spacebar is pressed"""
        if self.running and not self.transmitting:
            self.transmitting = True
            self.space_pressed = True
            if not self.is_host:
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
            if not self.is_host:
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
            if not self.is_host:
                self.transmit_btn.config(text="TRANSMITTING (SPACE)", bg=self.TRANSMIT_COLOR)
            self.status_var.set("STATUS: Transmitting")
            self.send_thread = threading.Thread(target=self.send_loop, daemon=True)
            self.send_thread.start()
            self.log("Started transmitting (button)")
        else:
            if not self.is_host:
                self.transmit_btn.config(text="TRANSMIT (SPACE)", bg=self.SECONDARY_COLOR)
            self.status_var.set("STATUS: Connected")
            self.log("Stopped transmitting (button)")
    
    def toggle_encryption(self):
        """Toggle encryption on/off with visual feedback"""
        self.encryption_enabled = not self.encryption_enabled
        if self.encryption_enabled:
            self.encryption_indicator.config(text="🔒", fg=self.ENCRYPTION_COLOR)
            if hasattr(self, 'host_encryption_btn'):
                self.host_encryption_btn.config(bg=self.ENCRYPTION_COLOR)
            if hasattr(self, 'encryption_btn'):
                self.encryption_btn.config(bg=self.ENCRYPTION_COLOR)
            self.log("Encryption enabled")
        else:
            self.encryption_indicator.config(text="⚠️", fg=self.ERROR_COLOR)
            if hasattr(self, 'host_encryption_btn'):
                self.host_encryption_btn.config(bg=self.DISABLED_COLOR)
            if hasattr(self, 'encryption_btn'):
                self.encryption_btn.config(bg=self.DISABLED_COLOR)
            self.log("Encryption disabled - WARNING: Communications are not secure!")
    
    def generate_mlkem_keys(self):
        """Generate ML-KEM key pair for post-quantum key exchange"""
        try:
            # Generate key pair using ML-KEM-1024
            public_key, secret_key = self.kem.keygen()
            self.log(f"Generated ML-KEM keys (pub: {len(public_key)} bytes, sec: {len(secret_key)} bytes)", 'debug')
            return public_key, secret_key
        except Exception as e:
            self.log(f"Error generating ML-KEM keys: {str(e)}", 'error')
            raise
    
    def encrypt_audio_data(self, data, key):
        """Encrypt audio data using AES-256-GCM with proper padding"""
        try:
            # Pad the data to be a multiple of 16 bytes
            pad_length = 16 - (len(data) % 16)
            data = data + bytes([pad_length] * pad_length)
            
            # Generate a random nonce
            nonce = get_random_bytes(12)
            
            # Create cipher object and encrypt the data
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            # Combine nonce + tag + ciphertext
            return nonce + tag + ciphertext
        except Exception as e:
            self.log(f"Error encrypting audio data: {str(e)}", 'error')
            if self.encryption_enabled:
                self.log("Falling back to unencrypted mode", 'warning')
                self.encryption_enabled = False
                return data
            raise
    
    def decrypt_audio_data(self, encrypted_data, key):
        """Decrypt audio data using AES-256-GCM with padding removal"""
        try:
            if len(encrypted_data) < 28:  # Minimum size for nonce + tag
                raise ValueError("Encrypted data too short")
                
            # Split the encrypted data into components
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher object and decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Remove padding
            pad_length = data[-1]
            if pad_length > 16:
                raise ValueError("Invalid padding")
            return data[:-pad_length]
        except Exception as e:
            self.log(f"Error decrypting audio data: {str(e)}", 'error')
            if self.encryption_enabled:
                self.log("Falling back to unencrypted mode", 'warning')
                self.encryption_enabled = False
            raise
    
    def perform_key_exchange(self, addr, is_host=False):
        """Perform post-quantum key exchange with verification"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.log(f"Starting key exchange (attempt {attempt+1}/{max_retries}) with {addr} (is_host={is_host})", 'debug')
                
                if is_host:
                    # Host uses pre-generated keys
                    public_key = self.host_public_key
                    secret_key = self.host_secret_key
                    
                    # Send public key to client with length prefix
                    key_msg = b'ORB_KEY_EXCHANGE' + struct.pack('!I', len(public_key)) + public_key
                    self.socket.sendto(key_msg, addr)
                    self.log(f"Sent public key ({len(public_key)} bytes) to {addr}", 'debug')
                    
                    # Wait for encapsulated key from client with timeout
                    ready = select.select([self.socket], [], [], 10.0)
                    if not ready[0]:
                        raise TimeoutError("Key exchange timeout waiting for encapsulated key")
                    
                    data, _ = self.socket.recvfrom(1024*16)  # Increased buffer size
                    if not data.startswith(b'ORB_ENCAPSULATED'):
                        raise ValueError("Invalid key exchange response - missing header")
                    
                    # Extract encapsulated key
                    cipher_text = data[len('ORB_ENCAPSULATED'):]
                    
                    # Decapsulate to get shared secret
                    shared_secret = self.kem.decaps(secret_key, cipher_text)
                    
                    # Derive AES key from shared secret
                    aes_key = hashlib.sha256(shared_secret).digest()
                    
                    # Verify the key works
                    test_data = b'ORB_TEST_DATA'
                    encrypted = self.encrypt_audio_data(test_data, aes_key)
                    decrypted = self.decrypt_audio_data(encrypted, aes_key)
                    if decrypted != test_data:
                        raise ValueError("Key verification failed")
                    
                    # Store the session key for this client
                    self.session_keys[addr] = {
                        'aes_key': aes_key,
                        'last_used': time.time()
                    }
                    
                    self.log(f"Key exchange completed with {addr}", 'debug')
                    return aes_key
                else:
                    # Client receives public key from host
                    self.log("Waiting for public key from host...", 'debug')
                    
                    # Clear socket buffer first
                    while True:
                        ready = select.select([self.socket], [], [], 0.1)
                        if not ready[0]:
                            break
                        self.socket.recvfrom(1024*16)
                    
                    # Send request for key exchange
                    self.socket.sendto(b'ORB_KEY_REQUEST', addr)
                    
                    # Wait for public key with timeout
                    ready = select.select([self.socket], [], [], 15.0)
                    if not ready[0]:
                        raise TimeoutError("Key exchange timeout waiting for public key")
                    
                    data, _ = self.socket.recvfrom(1024*16)
                    if not data.startswith(b'ORB_KEY_EXCHANGE'):
                        raise ValueError("Invalid key exchange initiation - missing header")
                    
                    # Extract public key length and data
                    key_len = struct.unpack('!I', data[len('ORB_KEY_EXCHANGE'):len('ORB_KEY_EXCHANGE')+4])[0]
                    public_key = data[len('ORB_KEY_EXCHANGE')+4:len('ORB_KEY_EXCHANGE')+4+key_len]
                    
                    # Generate encapsulated key and shared secret
                    cipher_text, shared_secret = self.kem.encaps(public_key)
                    
                    # Send encapsulated key to host
                    self.socket.sendto(b'ORB_ENCAPSULATED' + cipher_text, addr)
                    
                    # Derive AES key
                    aes_key = hashlib.sha256(shared_secret).digest()
                    
                    # Verify key by sending test message
                    test_data = b'ORB_TEST_DATA'
                    encrypted = self.encrypt_audio_data(test_data, aes_key)
                    self.socket.sendto(b'ORB_KEY_VERIFY' + encrypted, addr)
                    
                    # Wait for verification
                    ready = select.select([self.socket], [], [], 5.0)
                    if not ready[0]:
                        raise TimeoutError("Key verification timeout")
                    
                    data, _ = self.socket.recvfrom(1024)
                    if data != b'ORB_KEY_VALID':
                        raise ValueError("Key verification failed")
                    
                    # Store the key
                    self.client_key = {
                        'aes_key': aes_key,
                        'last_used': time.time()
                    }
                    
                    self.log("Key exchange completed with host")
                    return aes_key
                    
            except Exception as e:
                self.log(f"Key exchange attempt {attempt+1} failed: {str(e)}", 'warning')
                if attempt == max_retries - 1:
                    self.log("Key exchange failed after maximum retries", 'error')
                    raise
                time.sleep(1)
    
    def rotate_keys_if_needed(self):
        """Rotate session keys if the rotation interval has passed"""
        if not self.encryption_enabled:
            return
        
        current_time = time.time()
        if current_time - self.last_key_rotation > self.key_rotation_interval:
            self.log("Rotating session keys...")
            
            if self.is_host:
                # Rotate keys for all connected clients
                for addr in list(self.session_keys.keys()):
                    try:
                        new_key = self.perform_key_exchange(addr, is_host=True)
                        self.session_keys[addr]['aes_key'] = new_key
                        self.session_keys[addr]['last_used'] = current_time
                        self.log(f"Successfully rotated key for {addr}")
                    except Exception as e:
                        self.log(f"Failed to rotate key for {addr}: {str(e)}", 'warning')
                        del self.session_keys[addr]
            else:
                # Rotate key with host
                if self.client_key and self.host_address:
                    try:
                        new_key = self.perform_key_exchange(self.host_address, is_host=False)
                        self.client_key['aes_key'] = new_key
                        self.client_key['last_used'] = current_time
                        self.log("Successfully rotated key with host")
                    except Exception as e:
                        self.log(f"Failed to rotate key with host: {str(e)}", 'warning')
                        self.client_key = None
            
            self.last_key_rotation = current_time
    
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
        
        if self.is_host:
            # Lock host UI elements
            self.port_entry.config(state=state)
            self.host_name_entry.config(state=state)
            self.password_entry.config(state=state)
        else:
            # Lock client UI elements
            self.host_entry.config(state=state)
            self.client_port_entry.config(state=state)
            self.client_name_entry.config(state=state)
            self.client_password_entry.config(state=state)
            
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
    
    def verify_connection(self, host, port, password):
        """Verify that the host is actually running an ORB server and password is correct"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_socket.settimeout(2)
            
            # Send verification packet
            test_socket.sendto(b'ORB_VERIFY:' + password.encode(), (host, port))
            
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
    
    def broadcast_avatars(self):
        """Broadcast avatar data to all clients"""
        try:
            # Create a serializable version of avatar data
            serializable_avatars = {}
            for addr, data in self.avatar_data.items():
                try:
                    # Convert address tuple to "ip:port" string
                    addr_str = f"{addr[0]}:{addr[1]}"
                    serializable_avatars[addr_str] = data
                except Exception as e:
                    self.log(f"Error processing avatar for {addr}: {str(e)}", 'error')
                    continue

            # Prepare the message
            avatar_msg = {
                'type': 'avatar_update',
                'avatars': serializable_avatars,
                'timestamp': time.time()  # Add timestamp for debugging
            }

            # Broadcast to all participants
            success_count = 0
            for addr in list(self.participants.keys()):
                try:
                    # Skip sending to ourselves
                    if addr == ('0.0.0.0', self.port):
                        continue
                        
                    # Serialize and send
                    msg_json = json.dumps(avatar_msg)
                    self.socket.sendto(msg_json.encode(), addr)
                    success_count += 1
                    self.log(f"Sent avatar update to {addr}", 'debug')
                except Exception as e:
                    self.log(f"Error sending avatars to {addr}: {str(e)}", 'error')
                    # Remove disconnected clients
                    if addr in self.participants:
                        del self.participants[addr]
                    if addr in self.avatar_data:
                        del self.avatar_data[addr]

            self.log(f"Broadcast avatars to {success_count}/{len(self.participants)-1} clients", 'debug')
            
        except Exception as e:
            self.log(f"Critical error in broadcast_avatars: {str(e)}", 'error')
            # Attempt to recover by clearing bad data
            self.avatar_data = {}
    
    def handle_new_client(self, addr, join_message):
        """Handle new client connection with avatar data"""
        # Verify password if provided
        if 'password' in join_message and join_message['password'] != self.password:
            self.log(f"Client {addr} provided incorrect password", 'warning')
            self.socket.sendto(b'ORB_PASSWORD_INCORRECT', addr)
            return
        
        if addr not in self.participants:
            # Set client name from join message or generate one
            client_name = join_message.get('name', f"Guest-{random.randint(100,999)}")
            self.participants[addr] = client_name
            self.log(f"New connection from {addr} as {client_name}")
        
        # Store avatar data if provided
        if 'avatar' in join_message:
            self.avatar_data[addr] = join_message['avatar']
            self.log(f"Stored avatar data for {addr}: {join_message['avatar']}")
        
        # Send host name and participant list to new client
        self.broadcast_participant_list()
        
        # Broadcast updated avatars to all clients
        self.broadcast_avatars()
        
        # If encryption is enabled, perform key exchange
        if self.encryption_enabled:
            try:
                # Send public key to client with length prefix
                public_key = self.host_public_key
                key_msg = b'ORB_KEY_EXCHANGE' + struct.pack('!I', len(public_key)) + public_key
                self.socket.sendto(key_msg, addr)
                self.log(f"Sent public key ({len(public_key)} bytes) to {addr}", 'debug')
                
                # Wait for encapsulated key from client with timeout
                ready = select.select([self.socket], [], [], 10.0)
                if not ready[0]:
                    raise TimeoutError("Key exchange timeout waiting for encapsulated key")
                
                data, _ = self.socket.recvfrom(1024*16)
                if not data.startswith(b'ORB_ENCAPSULATED'):
                    raise ValueError("Invalid key exchange response - missing header")
                
                # Process encapsulated key
                cipher_text = data[len('ORB_ENCAPSULATED'):]
                shared_secret = self.kem.decaps(self.host_secret_key, cipher_text)
                aes_key = hashlib.sha256(shared_secret).digest()
                
                # Store session key
                self.session_keys[addr] = {
                    'aes_key': aes_key,
                    'last_used': time.time()
                }
                
                self.log(f"Key exchange completed with {addr}")
                
                # Send verification
                self.socket.sendto(b'ORB_KEY_VALID', addr)
                
            except Exception as e:
                self.log(f"Key exchange failed for {addr}: {str(e)}", 'error')
                if self.encryption_enabled:
                    self.log("Falling back to unencrypted mode for this client", 'warning')
                    self.socket.sendto(b'ORB_KEY_INVALID', addr)
    
    def start_audio_streams(self):
        """Start audio input/output streams"""
        try:
            self.input_stream = self.pyaudio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=44100,
                input=True,
                frames_per_buffer=1024,
                start=False
            )
            
            self.output_stream = self.pyaudio.open(
                format=pyaudio.paInt16,
                channels=1,
                rate=44100,
                output=True,
                frames_per_buffer=1024,
                start=False
            )
            
            self.input_stream.start_stream()
            self.output_stream.start_stream()
            self.log("Audio streams started successfully")
        except Exception as e:
            self.log(f"Error starting audio streams: {str(e)}", 'error')
            raise
    
    def start_host(self):
        """Start the host/server mode"""
        try:
            # Get host configuration
            self.port = int(self.port_entry.get())
            self.host_name = self.host_name_entry.get()
            self.password = self.password_var.get()
            
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
                
                # Start audio streams
                self.start_audio_streams()
                
                # Start network thread
                self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
                self.receive_thread.start()
                
                # Start update thread
                self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
                self.update_thread.start()
                
                # Update UI
                self.status_var.set(f"Hosting ORB '{self.host_name}' on port {self.port}")
                self.status_indicator.config(fg=self.RECEIVE_COLOR)
                self.start_host_btn.config(state=tk.DISABLED)
                self.seal_chamber_btn.config(state=tk.NORMAL)
                self.lock_ui(True)
                
                self.log("ORB Host started successfully")
                
            except Exception as e:
                raise ConnectionError(f"Failed to bind to port {self.port}: {str(e)}")
        
        except Exception as e:
            self.status_indicator.config(fg=self.ERROR_COLOR)
            error_msg = str(e)
            self.log(f"Host start error: {error_msg}", 'error')
            messagebox.showerror("HOST ERROR", error_msg)
            self.stop_host()
    
    def stop_host(self):
        """Stop the host/server mode"""
        self.log("Stopping ORB Host...")
        self.running = False
        
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
        self.participants.clear()
        self.avatar_data.clear()
        
        # Update UI
        self.status_var.set("ORB: Ready")
        self.status_indicator.config(fg="#666666")
        self.start_host_btn.config(state=tk.NORMAL)
        self.seal_chamber_btn.config(state=tk.DISABLED)
        self.lock_ui(False)
        
        self.log("ORB Host stopped")
    
    def start_connection(self):
        """Start client connection to host"""
        try:
            host = self.host_entry.get()
            port = int(self.client_port_entry.get())
            password = self.client_password_entry.get()
        
            # Store client name
            self.client_name = self.client_name_var.get()
            self.host_address = (host, port)
        
            # Get selected devices
            self.selected_input_idx = int(self.input_dev_combo.get().split(":")[0])
            self.selected_output_idx = int(self.output_dev_combo.get().split(":")[0])
        
            # Setup socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
            # Verify connection before proceeding
            self.status_var.set(f"VERIFYING CONNECTION TO: {host}:{port}")
            self.root.update()
        
            if not self.verify_connection(host, port, password):
                raise ConnectionError(f"Could not connect to ORB server at {host}:{port} or password incorrect")
        
            # Send client name immediately after connecting
            self.socket.sendto(b'ORB_CLIENT_NAME' + self.client_name.encode(), (host, port))
        
            # Send avatar data as a properly formatted JSON message
            join_message = {
                'type': 'join',
                'name': self.client_name,
                'avatar': {
                    'body': self.body_var.get(),
                    'top': self.top_var.get(),
                    'head': self.head_var.get()
                },
                'password': password
            }
            self.socket.sendto(json.dumps(join_message).encode(), (host, port))
        
            self.status_var.set(f"CONNECTED TO: {host}:{port}")
            self.status_indicator.config(fg=self.RECEIVE_COLOR)
            self.log(f"Connected to {host}:{port} as '{self.client_name}'")
            
            # Perform key exchange if encryption is enabled
            if self.encryption_enabled:
                try:
                    self.perform_key_exchange((host, port), is_host=False)
                except Exception as e:
                    self.log(f"Initial key exchange failed: {str(e)}", 'error')
                    if self.encryption_enabled:
                        raise ConnectionError("Failed to establish encrypted connection")
            
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
            
            # Hide configuration UI and show chamber/participants
            self.dev_frame.pack_forget()
            self.creator_frame.pack_forget()
            self.client_chamber_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
            self.client_participants_frame.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)
            
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
        """Stop client connection"""
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
        self.client_key = None
        self.participants = {}
        self.host_name = ""
        
        # Update UI
        self.connect_btn.config(text="CONNECT")
        self.transmit_btn.config(state=tk.DISABLED, bg=self.SECONDARY_COLOR)
        self.status_var.set("ORB: Ready")
        self.status_indicator.config(fg="#666666")
        self.orb_label.config(fg=self.IDLE_COLOR)
        self.client_participants_list.delete(0, tk.END)
        self.host_name_var.set("")
        self.client_chamber_canvas.delete("all")
        
        # Show configuration UI and hide chamber/participants
        self.dev_frame.pack(fill=tk.X, pady=10, padx=10)
        self.creator_frame.pack(pady=10, fill=tk.X, padx=10)
        self.client_chamber_frame.pack_forget()
        self.client_participants_frame.pack_forget()
        
        # Unlock UI
        self.lock_ui(False)
        self.log("Connection fully stopped")
    
    def receive_loop(self):
        self.log("Receive loop started")
        while self.running:
            try:
                ready = select.select([self.socket], [], [], 0.1)
                if ready[0]:
                    data, addr = self.socket.recvfrom(1024*16)  # Increased buffer size
                    
                    # Handle verification requests (host mode)
                    if self.is_host and data == b'ORB_VERIFY':
                        self.socket.sendto(b'ORB_ACK', addr)
                        continue
                    
                    # Handle password verification (host mode)
                    if self.is_host and data.startswith(b'ORB_VERIFY:'):
                        password = data[len('ORB_VERIFY:'):].decode()
                        if password == self.password:
                            self.socket.sendto(b'ORB_ACK', addr)
                        else:
                            self.socket.sendto(b'ORB_PASSWORD_INCORRECT', addr)
                        continue
                    
                    # Handle key exchange requests (host mode)
                    if data == b'ORB_KEY_REQUEST' and self.is_host and self.encryption_enabled:
                        # Host responds to key request
                        public_key = self.host_public_key
                        key_msg = b'ORB_KEY_EXCHANGE' + struct.pack('!I', len(public_key)) + public_key
                        self.socket.sendto(key_msg, addr)
                        continue
                    
                    # Handle client name announcement (host mode)
                    if self.is_host and data.startswith(b'ORB_CLIENT_NAME'):
                        client_name = data[len('ORB_CLIENT_NAME'):].decode()
                        self.participants[addr] = client_name
                        self.log(f"Client {addr} set name to: {client_name}")
                        self.broadcast_participant_list()
                        continue
                    
                    # Handle participant list updates (client mode)
                    if not self.is_host and data.startswith(b'ORB_PARTICIPANTS'):
                        try:
                            participants_data = data[len('ORB_PARTICIPANTS'):].decode()
                            self.participants = eval(participants_data)
                            self.log(f"Updated participant list: {self.participants}")
                            continue
                        except Exception as e:
                            self.log(f"Error processing participant list: {str(e)}", 'error')
                            continue
                    
                    # Handle host name announcement (client mode)
                    if not self.is_host and data.startswith(b'ORB_HOST_NAME'):
                        self.host_name = data[len('ORB_HOST_NAME'):].decode()
                        self.host_name_var.set(f"HOST: {self.host_name}")
                        self.log(f"Host name set to: {self.host_name}")
                        continue
                    
                    # Handle avatar updates (both modes)
                    try:
                        message = json.loads(data.decode())
                        if message['type'] == 'avatar_update':
                            if self.is_host:
                                # Host should ignore these messages
                                continue
                            else:
                                self.update_chamber_view(message['avatars'])
                                continue
                    except:
                        pass
                    
                    # Handle join requests (host mode)
                    try:
                        if self.is_host and len(data) < 1024:  # Only try to decode JSON for small packets
                            message = json.loads(data.decode())
                            self.log(f"Received message: {message}", 'debug')
                            
                            if message.get('type') == 'join':
                                self.handle_new_client(addr, message)
                                continue
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass  # This is audio data, not JSON
                    
                    # Handle key exchange initiation (both modes)
                    if data.startswith(b'ORB_KEY_EXCHANGE') and self.encryption_enabled:
                        try:
                            # Extract public key length and data
                            key_len = struct.unpack('!I', data[len('ORB_KEY_EXCHANGE'):len('ORB_KEY_EXCHANGE')+4])[0]
                            public_key = data[len('ORB_KEY_EXCHANGE')+4:len('ORB_KEY_EXCHANGE')+4+key_len]
                            
                            if self.is_host:
                                # Host should ignore key exchange initiations
                                continue
                            else:
                                # Client generates encapsulated key and shared secret
                                cipher_text, shared_secret = self.kem.encaps(public_key)
                                
                                # Send encapsulated key to host
                                self.socket.sendto(b'ORB_ENCAPSULATED' + cipher_text, addr)
                                
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
                    
                    # Handle encapsulated key (both modes)
                    if data.startswith(b'ORB_ENCAPSULATED') and self.encryption_enabled:
                        try:
                            # Extract encapsulated key
                            cipher_text = data[len('ORB_ENCAPSULATED'):]
                            
                            if self.is_host:
                                # Host decapsulates to get shared secret
                                shared_secret = self.kem.decaps(self.host_secret_key, cipher_text)
                                
                                # Derive AES key from shared secret
                                aes_key = hashlib.sha256(shared_secret).digest()
                                
                                # Store the session key for this client
                                self.session_keys[addr] = {
                                    'aes_key': aes_key,
                                    'last_used': time.time()
                                }
                                
                                self.log(f"Key exchange completed with {addr}")
                            else:
                                # Client should ignore encapsulated keys
                                continue
                        except Exception as e:
                            self.log(f"Key exchange failed: {str(e)}", 'error')
                        continue
                    
                    # Handle key verification (host mode)
                    if data.startswith(b'ORB_KEY_VERIFY') and self.encryption_enabled and self.is_host:
                        try:
                            encrypted = data[len('ORB_KEY_VERIFY'):]
                            decrypted = self.decrypt_audio_data(encrypted, self.session_keys[addr]['aes_key'])
                            if decrypted == b'ORB_TEST_DATA':
                                self.socket.sendto(b'ORB_KEY_VALID', addr)
                            else:
                                self.socket.sendto(b'ORB_KEY_INVALID', addr)
                        except:
                            self.socket.sendto(b'ORB_KEY_INVALID', addr)
                        continue
                    
                    # Decrypt data if encryption is enabled
                    decrypted_data = data
                    if self.encryption_enabled:
                        try:
                            if self.is_host and addr in self.session_keys:
                                decrypted_data = self.decrypt_audio_data(data, self.session_keys[addr]['aes_key'])
                                self.session_keys[addr]['last_used'] = time.time()
                            elif not self.is_host and self.client_key:
                                decrypted_data = self.decrypt_audio_data(data, self.client_key['aes_key'])
                                self.client_key['last_used'] = time.time()
                            else:
                                # New client - initiate key exchange
                                if self.is_host:
                                    self.perform_key_exchange(addr, is_host=True)
                                continue
                        except Exception as e:
                            self.log(f"Decryption failed: {str(e)}", 'warning')
                            continue
                    
                    # Host mode: broadcast to all other connections
                    if self.is_host:
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
                                if connection[0] in self.avatar_data:
                                    del self.avatar_data[connection[0]]
                                self.broadcast_participant_list()
                                self.broadcast_avatars()
                    
                    # Play received audio
                    try:
                        if self.output_stream:
                            self.output_stream.write(decrypted_data)
                    except Exception as e:
                        self.log(f"Error playing audio: {str(e)}", 'error')
                    
                    self.last_activity = time.time()
                    self.activity_history.append(("receive", time.time()))
                    
                    # Rotate keys if needed
                    self.rotate_keys_if_needed()
                
            except (socket.timeout, BlockingIOError):
                continue
            except OSError as e:
                if self.running:
                    # Clean up disconnected clients (host mode)
                    if self.is_host:
                        for addr in list(self.participants.keys()):
                            try:
                                self.socket.sendto(b'ORB_PING', addr)
                            except:
                                # Client is disconnected
                                if addr in self.participants:
                                    del self.participants[addr]
                                if addr in self.avatar_data:
                                    del self.avatar_data[addr]
                                self.connections = [c for c in self.connections if c[0] != addr]
                                if addr in self.session_keys:
                                    del self.session_keys[addr]
                                self.log(f"Removed disconnected client: {addr}")
                                self.broadcast_participant_list()
                                self.broadcast_avatars()
                    else:
                        # Client mode - connection lost
                        self.log(f"Socket error in receive loop: {str(e)}", 'error')
                        if self.running:
                            self.stop_connection()
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
                        if self.is_host:
                            # Host doesn't send audio to clients in this loop
                            continue
                        elif self.client_key:
                            encrypted_data = self.encrypt_audio_data(data, self.client_key['aes_key'])
                            self.client_key['last_used'] = time.time()
                    except Exception as e:
                        self.log(f"Encryption failed: {str(e)}", 'warning')
                        continue
                
                try:
                    if not self.is_host and self.host_address:
                        self.socket.sendto(encrypted_data if self.encryption_enabled else data, self.host_address)
                except Exception as e:
                    self.log(f"Error sending to host: {str(e)}", 'error')
                    if not self.is_host and self.running:
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
                if self.is_host:
                    # Host mode - update participants listbox
                    self.participants_list.delete(0, tk.END)
                    
                    # Show host name
                    self.participants_list.insert(tk.END, f"{self.host_name} (Host)")
                    
                    # Show all participants
                    for addr, name in self.participants.items():
                        self.participants_list.insert(tk.END, name)
                else:
                    # Client mode - update participants listbox
                    self.client_participants_list.delete(0, tk.END)
                    
                    # Show host name if available
                    if self.host_name:
                        self.client_participants_list.insert(tk.END, f"{self.host_name} (Host)")
                    
                    # Show all participants
                    for addr, name in self.participants.items():
                        if addr != self.host_address:  # Skip host if already shown
                            self.client_participants_list.insert(tk.END, name)
                    
                    # Show client's own name
                    self.client_participants_list.insert(tk.END, f"{self.client_name} (You)")
                
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
        
        if self.is_host:
            self.stop_host()
        else:
            self.stop_connection()
            
        self.root.destroy()
        self.log("Application closed")

if __name__ == "__main__":
    root = tk.Tk()
    app = ORBv3(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()