#!/usr/bin/env python3
# generate_certificates.py - Genera certificati SSL per il server C2

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import os

def generate_self_signed_cert():
    """Genera un certificato autofirmato per testing"""
    
    # Genera chiave privata RSA 2048-bit
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Crea subject e issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Red Team C2"),
        x509.NameAttribute(NameOID.COMMON_NAME, "c2-server.local"),
    ])
    
    # Crea certificato
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("c2-server.local"),
            x509.IPAddress("127.0.0.1"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    return private_key, cert

def save_certificates(private_key, cert, key_file="server.key", cert_file="server.crt"):
    """Salva chiave privata e certificato su file"""
    
    # Salva chiave privata
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Salva certificato
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def main():
    """Funzione principale"""
    print("=== Generating SSL Certificates for C2 Server ===")
    
    # Verifica se i file già esistono
    if os.path.exists("server.key") and os.path.exists("server.crt"):
        print("Certificate files already exist.")
        print("server.key and server.crt found in current directory.")
        return True
    
    try:
        # Genera certificati
        private_key, cert = generate_self_signed_cert()
        
        # Salva su file
        save_certificates(private_key, cert)
        
        print("✓ SSL certificates generated successfully!")
        print("✓ server.key - Private key (RSA 2048-bit)")
        print("✓ server.crt - Self-signed certificate")
        print("\nCertificate Details:")
        print(f"  Subject: {cert.subject}")
        print(f"  Issuer: {cert.issuer}")
        print(f"  Valid From: {cert.not_valid_before}")
        print(f"  Valid Until: {cert.not_valid_after}")
        print(f"  Serial Number: {cert.serial_number}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error generating certificates: {e}")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n✓ Server is ready to use with HTTPS")
    else:
        print("\n✗ Failed to generate certificates")
        print("Please check OpenSSL/cryptography installation")