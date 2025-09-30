![STYX Banner](../styx1.png)

# 🏗️ STYX Architecture Documentation

> **© 2024 Sebastian Martin. All rights reserved.**
> This documentation is proprietary and confidential. Unauthorized use, redistribution, or modification is strictly prohibited.

## 📋 System Architecture

## 📋 System Architecture

### High-Level Overview

```mermaid
graph TB
    subgraph "Client Environment"
        A[C++ Client] --> B[Windows API]
        B --> C[System Resources]
    end
    
    subgraph "Network Transport"
        D[HTTPS/TLS 1.2+] --> E[Encrypted Communication]
    end
    
    subgraph "Server Environment"
        F[Python Server] --> G[Cryptography Engine]
        G --> H[Session Management]
        H --> I[Command Processing]
    end
    
    subgraph "Operator Interface"
        J[Management Console] --> K[Real-time Monitoring]
        K --> L[Command Execution]
    end
    
    A --> D
    D --> F
    F --> J
    J --> F
```

## 🔄 Communication Flow

### Initial Key Exchange Sequence

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Phase 1 - Key Exchange
    
    Client->>Server: POST /key_exchange<br/>RSA-OAEP(encrypted_session_key)
    Server->>Server: RSA decrypt session key
    Server->>Client: AES-GCM(IV+TAG+"KEY_EXCHANGE_OK")
    
    Note over Client,Server: Session key established
    Client->>Server: Store session key
    Server->>Server: Store client session key
```

### Beaconing and Command Execution

```mermaid
sequenceDiagram
    participant Operator
    participant Server
    participant Client
    
    Note over Client,Server: Phase 2 - Beaconing Loop
    
    Client->>Server: POST /api/report<br/>AES-GCM(beacon_data)
    Server->>Server: Decrypt beacon, update client state
    Server->>Operator: Display client activity
    
    Operator->>Server: Queue command for client
    Server->>Client: AES-GCM(encrypted_command)
    
    Client->>Client: Execute command
    Client->>Server: AES-GCM(command_output)
    Server->>Operator: Display command results
    
    Note over Client,Server: Loop continues with configurable interval
```

## 🏛️ Component Architecture

### C++ Client Architecture

```mermaid
graph TD
    subgraph "C++ Client Components"
        A[Main Execution Loop] --> B[Cryptography Module]
        A --> C[Communication Module]
        A --> D[Stealth Module]
        A --> E[Persistence Module]
        A --> F[Data Collection]
        
        B --> B1[RSA-OAEP Key Exchange]
        B --> B2[AES-256-GCM Encryption]
        B --> B3[String Obfuscation]
        
        C --> C1[WinHTTP Client]
        C --> C2[Certificate Pinning]
        C --> C3[Beacon Scheduling]
        
        D --> D1[Debugger Detection]
        D --> D2[VM Detection]
        D --> D3[Process Hiding]
        
        E --> E1[Registry Persistence]
        E --> E2[Scheduled Tasks]
        E --> E3[Service Installation]
        
        F --> F1[Keylogging]
        F --> F2[Screenshot Capture]
        F --> F3[System Reconnaissance]
    end
```

### Python Server Architecture

```mermaid
graph TD
    subgraph "Python Server Components"
        A[HTTP Server] --> B[Cryptography Engine]
        A --> C[Session Management]
        A --> D[Command Processing]
        A --> E[Logging System]
        
        B --> B1[RSA Key Management]
        B --> B2[AES-GCM Operations]
        B --> B3[Certificate Handling]
        
        C --> C1[Client State Tracking]
        C --> C2[Thread-safe Access]
        C --> C3[Session Timeout]
        
        D --> D1[Command Queueing]
        D --> D2[Result Processing]
        D --> D3[Output Formatting]
        
        E --> E1[Operational Logging]
        E --> E2[Security Auditing]
        E --> E3[Performance Monitoring]
    end
    
    subgraph "Management Interface"
        F[Operator Console] --> G[Real-time Updates]
        F --> H[Command Input]
        F --> I[Status Display]
    end
    
    A --> F
    F --> A
```

## 🔐 Cryptographic Architecture

### Encryption Flow

```mermaid
flowchart TD
    A[Client Session Key] --> B{Encrypt Data}
    B --> C[Generate Random IV]
    C --> D[AES-256-GCM Encrypt]
    D --> E[Add Authentication Tag]
    E --> F[Transmit IV + Tag + Ciphertext]
    
    G[Server Session Key] --> H{Decrypt Data}
    H --> I[Extract IV and Tag]
    I --> J[AES-256-GCM Decrypt]
    J --> K[Verify Authentication Tag]
    K --> L[Process Plaintext]
```

### Key Exchange Protocol

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    
    Note over C,S: Step 1 - Client Preparation
    C->>C: Generate random session key (32 bytes)
    C->>C: Load server public key from header
    
    Note over C,S: Step 2 - Secure Transmission
    C->>S: RSA-OAEP encrypt(session_key)
    S->>S: RSA decrypt with private key
    
    Note over C,S: Step 3 - Session Establishment
    S->>S: Store session key for client
    S->>C: AES-GCM confirm encryption
    C->>C: Store session key for server
    
    Note over C,S: Secure channel established
```

## 📊 Data Flow Architecture

### Beacon Data Structure

```mermaid
flowchart LR
    A[Client System] --> B[Collect Data]
    B --> C[Format Beacon]
    C --> D[Encrypt with AES-GCM]
    D --> E[HTTPS POST to Server]
    
    F[Server] --> G[Decrypt Beacon]
    G --> H[Parse Beacon Data]
    H --> I[Update Client State]
    I --> J[Display to Operator]
    
    K[Operator] --> L[Queue Command]
    L --> M[Encrypt Command]
    M --> N[Store for Next Beacon]
```

### Beacon Format
```
BEACON|username|hostname|process_id|additional_data
```

## 🎯 Operational Architecture

### Client Deployment Flow

```mermaid
flowchart TD
    A[Compile Client] --> B[Deploy to Target]
    B --> C[Establish Persistence]
    C --> D[Initial Key Exchange]
    D --> E[Begin Beaconing]
    
    F[Server Running] --> G[Accept Connections]
    G --> H[Manage Sessions]
    H --> I[Process Commands]
    
    J[Operator Connected] --> K[Monitor Clients]
    K --> L[Issue Commands]
    L --> M[View Results]
```

### Command Execution Flow

```mermaid
sequenceDiagram
    participant O as Operator
    participant S as Server
    participant C as Client
    
    O->>S: Issue command "exec whoami"
    S->>S: Encrypt command with client session key
    S->>S: Store in pending commands queue
    
    C->>S: Regular beacon request
    S->>S: Check for pending commands
    S->>C: Respond with encrypted command
    
    C->>C: Execute command "whoami"
    C->>C: Capture command output
    C->>S: Next beacon includes command output
    
    S->>S: Decrypt and process output
    S->>O: Display command results
```

## 🛡️ Security Architecture

### Defense-in-Depth Approach

```mermaid
graph TB
    subgraph "Transport Security"
        A[TLS 1.2+ Encryption]
        B[Certificate Pinning]
        C[Perfect Forward Secrecy]
    end
    
    subgraph "Application Security"
        D[End-to-End Encryption]
        E[Authenticated Encryption]
        F[Session-based Keys]
    end
    
    subgraph "Operational Security"
        G[Stealth Techniques]
        H[Anti-Analysis]
        I[Persistence Mechanisms]
    end
    
    subgraph "Management Security"
        J[Access Controls]
        K[Audit Logging]
        L[Configuration Hardening]
    end
```

### Threat Mitigation

```mermaid
flowchart LR
    A[Network Detection] --> B[TLS Encryption]
    B --> C[Certificate Validation]
    
    D[Memory Analysis] --> E[String Obfuscation]
    E --> F[Runtime Protection]
    
    G[Process Monitoring] --> H[Stealth Techniques]
    H --> I[Legitimate Appearance]
    
    J[Forensic Analysis] --> K[Ephemeral Keys]
    K --> L[Minimal Footprint]
```

## 📈 Performance Architecture

### Scalability Design

```mermaid
graph LR
    A[Single Server] --> B[Multiple Clients]
    B --> C[Load Balancing]
    C --> D[High Availability]
    
    E[Session Management] --> F[Connection Pooling]
    F --> G[Resource Optimization]
    
    H[Command Processing] --> I[Async Operations]
    I --> J[Parallel Execution]
```

### Resource Management

```mermaid
flowchart TD
    A[Client Connection] --> B[Session Creation]
    B --> C[Memory Allocation]
    C --> D[Crypto Context]
    
    E[Beacon Processing] --> F[Thread Pool]
    F --> G[Concurrent Handling]
    G --> H[Response Generation]
    
    I[Command Execution] --> J[Queue Management]
    J --> K[Priority Handling]
    K --> L[Result Storage]
```

## 🔄 Lifecycle Management

### Client Lifecycle

```mermaid
graph TB
    A[Compilation] --> B[Deployment]
    B --> C[Initial Execution]
    C --> D[Persistence Setup]
    D --> E[Key Exchange]
    E --> F[Beaconing]
    F --> G[Command Execution]
    G --> H[Update/Remove]
```

### Server Lifecycle

```mermaid
graph TB
    A[Configuration] --> B[Key Generation]
    B --> C[Server Startup]
    C --> D[Client Management]
    D --> E[Command Processing]
    E --> F[Monitoring]
    F --> G[Maintenance]
    G --> H[Shutdown]
```

## 🧩 Integration Architecture

### External Integration Points

```mermaid
graph LR
    A[Client] --> B[Windows API]
    A --> C[Cryptographic APIs]
    A --> D[Network Stack]
    
    E[Server] --> F[Python Ecosystem]
    E --> G[Web Framework]
    E --> H[Database Systems]
    
    I[Management] --> J[CLI Interface]
    I --> K[Web Interface]
    I --> L[API Endpoints]
```

### Extension Points

```mermaid
graph TD
    A[Plugin System] --> B[Custom Commands]
    A --> C[Data Collection Modules]
    A --> D[Persistence Methods]
    
    E[API Integration] --> F[REST API]
    E --> G[WebSocket Support]
    E --> H[Database Backend]
    
    I[Reporting] --> J[Log Export]
    I --> K[Dashboard Integration]
    I --> L[Alerting System]
```

---

*This architecture represents a sophisticated C2 framework designed for authorized security testing. All components implement defense-in-depth security principles and follow industry best practices.*