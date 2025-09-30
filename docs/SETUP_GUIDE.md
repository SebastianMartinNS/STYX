![STYX Banner](../styx1.png)

# 🛠️ STYX Setup Guide

> **© 2024 Sebastian Martin. All rights reserved.**
> This documentation is proprietary and confidential. Unauthorized use, redistribution, or modification is strictly prohibited.

## 📋 Prerequisites

### System Requirements

**Server (Python):**
- Python 3.8+
- OpenSSL 1.1.1+
- 2GB+ RAM
- 10GB+ disk space

**Client (C++):**
- Windows 10/11 (x64)
- Visual Studio 2019+ with C++ build tools
- Windows SDK 10.0.19041.0+

### Required Software

```bash
# Python dependencies
pip install cryptography==41.0.7
pip install pyopenssl==23.2.0

# Development tools
# - Visual Studio 2019+ with C++ desktop development
# - Windows SDK
# - OpenSSL for Windows (optional)
```

## 📁 Project Structure

```
c2client/
├── docs/                    # Documentation
│   ├── DISCLAIMER.md       # Legal and ethical guidelines
│   ├── CLIENT_GUIDE.md     # C++ client technical guide
│   ├── SERVER_GUIDE.md     # Python server technical guide
│   └── SETUP_GUIDE.md      # This setup guide
├── src/
│   ├── c2_server_advanced.py      # Python C2 server
│   └── lab_client_redt_advanced.cpp  # C++ client
├── certs/                   # SSL certificates
├── keys/                    # RSA keys
├── server_public_key.h      # Auto-generated public key
└── README.md               # Main documentation
```

## 🔐 SSL Certificate Generation

### Self-Signed Certificate (Development)

**Generate Certificate Authority:**
```bash
# Create private key for CA
openssl genrsa -out ca.key 2048

# Create CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=Styx CA"
```

**Generate Server Certificate:**
```bash
# Create server private key
openssl genrsa -out server.key 2048

# Create certificate signing request
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# Sign certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -set_serial 01 -out server.crt

# Verify certificate
openssl verify -CAfile ca.crt server.crt
```

### Production Certificate (Recommended)

**Use trusted CA:**
- Let's Encrypt
- Commercial certificate authority
- Enterprise PKI infrastructure

## 🐍 Python Server Setup

### 1. Install Python Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install required packages
pip install cryptography==41.0.7
pip install pyopenssl==23.2.0
```

### 2. Configure Server

**Edit server configuration:**
```python
# In c2_server_advanced.py, modify these constants:
C2_PORT = 8443              # HTTPS port
C2_HOST = "0.0.0.0"         # Bind to all interfaces
SSL_CERT_FILE = "certs/server.crt"
SSL_KEY_FILE = "certs/server.key"
```

### 3. Generate RSA Keys

**First-time setup:**
```bash
# The server will auto-generate keys on first run
# Or manually generate:
python -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save private key
with open('keys/server_private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key
public_key = private_key.public_key()
with open('keys/server_public_key.der', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    ))
"
```

### 4. Start the Server

**Run the C2 server:**
```bash
python src/c2_server_advanced.py
```

**Expected output:**
```
[INFO] Generating RSA keypair...
[INFO] RSA keys generated successfully
[INFO] Starting C2 server on https://0.0.0.0:8443
[INFO] Management interface ready. Type 'help' for commands
```

## 🛠️ C++ Client Compilation

### 1. Visual Studio Setup

**Required components:**
- Desktop development with C++
- Windows 10 SDK (10.0.19041.0 or later)
- C++ CMake tools for Windows

### 2. Project Configuration

**Create Visual Studio project:**

1. Open Visual Studio
2. Create new project → "Console App"
3. Name: "StyxClient"
4. Platform: x64
5. C++ version: C++17 or later

### 3. Configure Project Settings

**Additional Include Directories:**
- `$(WindowsSDK_IncludePath)`
- Path to Windows SDK headers

**Additional Library Directories:**
- `$(WindowsSDK_LibraryPath_x64)`
- Path to crypt32.lib, bcrypt.lib

**Preprocessor Definitions:**
- `_WIN32_WINNT=0x0A00` (Windows 10)
- `NTDDI_VERSION=0x0A000006` (Windows 10 2004)
- `WIN32_LEAN_AND_MEAN`
- `_CRT_SECURE_NO_WARNINGS`

### 4. Link Required Libraries

**Linker → Input → Additional Dependencies:**
```
ws2_32.lib
crypt32.lib
bcrypt.lib
winhttp.lib
advapi32.lib
user32.lib
shell32.lib
taskschd.lib
```

### 5. Copy Required Files

**Place in project directory:**
- `src/lab_client_redt_advanced.cpp` (main source)
- `server_public_key.h` (auto-generated by server)
- Any additional headers

### 6. Build Configuration

**Release build recommended:**
- Optimization: Maximize Speed (/O2)
- Debug information: None
- Whole program optimization: Yes
- Security features: Enable all

### 7. Compile the Client

**Build steps:**
1. Set configuration to "Release" and platform to "x64"
2. Build → Build Solution (Ctrl+Shift+B)
3. Executable will be in `x64/Release/`

**Command line compilation (alternative):**
```cmd
cl.exe /nologo /O2 /MT /W4 /DNDEBUG /D_WIN32_WINNT=0x0A00 ^
  /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um" ^
  /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared" ^
  lab_client_redt_advanced.cpp ^
  /link /SUBSYSTEM:CONSOLE ^
  ws2_32.lib crypt32.lib bcrypt.lib winhttp.lib advapi32.lib user32.lib shell32.lib taskschd.lib
```

## 🧪 Testing Environment Setup

### Isolated Network Configuration

**Recommended setup:**
```
+---------------------+      +---------------------+      +---------------------+
|   Attacker Machine  |------|   C2 Server         |------|   Target Machine    |
| (Operator)          |      | (Ubuntu/Python)     |      | (Windows/Client)    |
+---------------------+      +---------------------+      +---------------------+
```

### Virtual Machine Setup

**Using VirtualBox/VMware:**

1. **Server VM:**
   - Ubuntu 22.04 LTS
   - 2 vCPU, 4GB RAM, 20GB disk
   - Bridged network adapter
   - Python 3.10+

2. **Client VM:**
   - Windows 10/11
   - 2 vCPU, 2GB RAM, 30GB disk
   - NAT network (isolated)
   - Visual Studio Build Tools

### Network Configuration

**Server networking:**
```bash
# Ubuntu server network config
sudo nano /etc/netplan/01-netcfg.yaml

# Example configuration:
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: yes
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

**Firewall configuration:**
```bash
# Allow HTTPS traffic
sudo ufw allow 8443/tcp
sudo ufw enable
```

## 🔧 Client Configuration

### Compile-Time Configuration

**Edit client source constants:**
```cpp
// In lab_client_redt_advanced.cpp
const std::string C2_HOST = "192.168.1.100";  // Server IP
const std::string C2_PATH = "/api/report";
const int C2_PORT = 8443;
const int BEACON_JITTER = 30;  // Seconds between beacons
```

### Build-Time Options

**Debug vs Release features:**
- Debug build: Extensive logging, no stealth
- Release build: Stealth enabled, minimal logging

## 🚀 Deployment Checklist

### Pre-Deployment Verification

- [ ] SSL certificates generated and validated
- [ ] RSA keys generated and secured
- [ ] Server compiles without errors
- [ ] Client compiles without errors
- [ ] Network connectivity verified
- [ ] Firewall rules configured
- [ ] Test environment isolated

### First Run Procedure

1. **Start server:**
   ```bash
   python src/c2_server_advanced.py
   ```

2. **Verify server startup:**
   - Check for RSA key generation
   - Verify HTTPS server binding
   - Confirm management interface

3. **Deploy client:**
   - Copy compiled executable to target
   - Execute with appropriate permissions

4. **Monitor connections:**
   - Check server logs for client beacon
   - Verify encrypted communication
   - Test command execution

## 🔒 Security Hardening

### Server Security

**System hardening:**
```bash
# Update system
sudo apt update && sudo apt upgrade

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 8443/tcp
sudo ufw enable

# Create dedicated user
sudo adduser c2server
sudo usermod -aG sudo c2server

# File permissions
sudo chown -R c2server:c2server /opt/styx
sudo chmod 700 /opt/styx/keys
sudo chmod 600 /opt/styx/keys/*
```

### Certificate Security

**Best practices:**
- Use trusted certificate authority
- Regular certificate rotation
- Strong private key protection
- Certificate pinning validation

## 🐛 Troubleshooting

### Common Issues

**Server won't start:**
```bash
# Check port availability
netstat -tlnp | grep 8443

# Check certificate permissions
ls -la certs/

# Check Python dependencies
pip list | grep cryptography
```

**Client compilation errors:**
- Verify Windows SDK installation
- Check library paths
- Confirm Visual Studio components

**Connection issues:**
- Verify network connectivity
- Check firewall settings
- Validate SSL certificate

### Debug Mode

**Enable verbose logging:**
```python
# In server code, set logging level
export LOG_LEVEL=DEBUG

# Or modify directly:
logging.basicConfig(level=logging.DEBUG)
```

**Client debug build:**
- Compile with debug symbols
- Enable console output
- Disable stealth features

## 📊 Performance Testing

### Load Testing

**Simulate multiple clients:**
```python
# Simple load test script
import threading
import requests
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

def simulate_client(client_id):
    while True:
        try:
            response = requests.post(
                "https://localhost:8443/api/report",
                data=f"BEACON|user{client_id}|host{client_id}|1234",
                verify=False,
                timeout=10
            )
            print(f"Client {client_id}: {response.status_code}")
        except Exception as e:
            print(f"Client {client_id} error: {e}")

# Start multiple clients
for i in range(10):
    threading.Thread(target=simulate_client, args=(i,), daemon=True).start()
```

### Resource Monitoring

**Monitor server performance:**
```bash
# CPU usage
top -p $(pgrep -f c2_server)

# Memory usage
pmap -x $(pgrep -f c2_server)

# Network traffic
iftop -i eth0
```

## 🔄 Maintenance Procedures

### Regular Maintenance

**Daily tasks:**
- Review server logs
- Monitor system resources
- Check for security updates

**Weekly tasks:**
- Backup configuration and keys
- Rotate logs
- Verify certificate validity

**Monthly tasks:**
- Security audit
- Performance review
- Update dependencies

### Update Procedures

**Server updates:**
1. Stop server
2. Backup configuration
3. Update code
4. Test changes
5. Restart server

**Client updates:**
1. Compile new version
2. Test in isolated environment
3. Deploy to targets

---

*Always test thoroughly in isolated environments before deployment. Follow organizational change management procedures for production deployments.*