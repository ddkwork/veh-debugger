#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "remote_channel.h"
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <mutex>
#include <limits>
#include <cstring>
#include <chrono>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace veh::remote {
namespace {
bool Startup() {
    static const bool ok = [] { WSADATA data{}; return WSAStartup(MAKEWORD(2, 2), &data) == 0; }();
    return ok;
}
bool Unhex(const std::string& text, uint8_t* output, size_t size) {
    if (text.size() != size * 2) return false;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < size; ++i) {
        int a = digit(text[i * 2]), b = digit(text[i * 2 + 1]);
        if (a < 0 || b < 0) return false;
        output[i] = static_cast<uint8_t>((a << 4) | b);
    }
    return true;
}
bool Equal(const uint8_t* a, const uint8_t* b, size_t size) {
    volatile uint8_t different = 0;
    for (size_t i = 0; i < size; ++i) different = static_cast<uint8_t>(different | (a[i] ^ b[i]));
    return different == 0;
}
bool Fingerprint(PCCERT_CONTEXT certificate, const std::array<uint8_t, 32>& expected) {
    uint8_t hash[32]{};
    DWORD size = sizeof(hash);
    return certificate && CertVerifyTimeValidity(nullptr, certificate->pCertInfo) == 0 &&
        CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, certificate->pbCertEncoded,
            certificate->cbCertEncoded, hash, &size) && size == sizeof(hash) &&
        Equal(hash, expected.data(), sizeof(hash));
}
PCCERT_CONTEXT FindCertificate(const std::array<uint8_t, 32>& pin) {
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!store) return nullptr;
    PCCERT_CONTEXT found = nullptr, current = nullptr;
    while ((current = CertEnumCertificatesInStore(store, current))) {
        if (Fingerprint(current, pin)) { found = CertDuplicateCertificateContext(current); break; }
    }
    if (current) CertFreeCertificateContext(current);
    CertCloseStore(store, 0);
    return found;
}
// Deadlines are local monotonic milliseconds; never compared between hosts.
bool WaitSocket(SOCKET socket, bool writing, ULONGLONG deadline, HANDLE stop = nullptr) {
    for (;;) {
        if (stop && WaitForSingleObject(stop, 0) == WAIT_OBJECT_0) { SetLastError(ERROR_OPERATION_ABORTED); return false; }
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) { SetLastError(WAIT_TIMEOUT); return false; }
        fd_set set; FD_ZERO(&set); FD_SET(socket, &set);
        const auto remaining = std::min<ULONGLONG>(deadline - now, 100);
        timeval wait{0, static_cast<long>(remaining * 1000)};
        const int result = select(0, writing ? nullptr : &set, writing ? &set : nullptr, nullptr, &wait);
        if (result > 0) return true;
        if (result < 0) { SetLastError(ERROR_BROKEN_PIPE); return false; }
    }
}
bool RawWrite(SOCKET socket, const uint8_t* data, size_t size, ULONGLONG deadline) {
    while (size) {
        if (!WaitSocket(socket, true, deadline)) return false;
        int written = send(socket, reinterpret_cast<const char*>(data),
            static_cast<int>(std::min<size_t>(size, INT_MAX)), 0);
        if (written < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (written <= 0) { SetLastError(ERROR_BROKEN_PIPE); return false; }
        data += written; size -= written;
    }
    return true;
}
bool RawRead(SOCKET socket, std::vector<uint8_t>& data, ULONGLONG deadline, HANDLE stop = nullptr) {
    if (!WaitSocket(socket, false, deadline, stop)) return false;
    uint8_t buffer[16384];
    int read = recv(socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
    if (read <= 0) { SetLastError(ERROR_BROKEN_PIPE); return false; }
    if (data.size() + static_cast<size_t>(read) > 128 * 1024) { SetLastError(ERROR_INVALID_DATA); return false; }
    data.insert(data.end(), buffer, buffer + read);
    return true;
}
struct Budget {
    ULONGLONG deadline = 0;
    explicit Budget(int timeoutMs) {
        if (timeoutMs > 0) deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    }
    int Remaining() const {
        const auto now = GetTickCount64();
        if (!deadline || now >= deadline) { SetLastError(WAIT_TIMEOUT); return 0; }
        return static_cast<int>(std::min<ULONGLONG>(deadline - now, INT_MAX));
    }
};
bool PrivateFile(HANDLE file) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<uint8_t> tokenData(needed);
    const bool tokenOk = needed && GetTokenInformation(token, TokenUser, tokenData.data(), needed, &needed);
    CloseHandle(token);
    if (!tokenOk) return false;
    const PSID user = reinterpret_cast<TOKEN_USER*>(tokenData.data())->User.Sid;
    BYTE system[SECURITY_MAX_SID_SIZE], administrators[SECURITY_MAX_SID_SIZE];
    DWORD systemSize = sizeof(system), adminSize = sizeof(administrators);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize) ||
        !CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &adminSize)) return false;
    auto trusted = [&](PSID sid) {
        return sid && IsValidSid(sid) && (EqualSid(sid, user) || EqualSid(sid, system) || EqualSid(sid, administrators));
    };
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL acl = nullptr;
    PSID owner = nullptr;
    if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS) return false;
    bool ok = acl != nullptr && trusted(owner);
    constexpr DWORD sensitive = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES |
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_READ | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED;
    for (DWORD i = 0; ok && i < acl->AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(acl, i, &ace)) { ok = false; break; }
        const auto* header = static_cast<ACE_HEADER*>(ace);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
            if ((allowed->Mask & sensitive) && !trusted(const_cast<DWORD*>(&allowed->SidStart))) ok = false;
        } else if (header->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
                   header->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE ||
                   header->AceType == ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE) {
            // Conditional/object grants are not part of the private-token contract.
            ok = false;
        }
    }
    if (descriptor) LocalFree(descriptor);
    return ok;
}
struct Secret {
    std::array<uint8_t, 32> bytes{};
    ~Secret() { SecureZeroMemory(bytes.data(), bytes.size()); }
    bool Load(const std::wstring& path) {
        struct File {
            HANDLE handle = INVALID_HANDLE_VALUE;
            ~File() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
        } file;
        file.handle = CreateFileW(path.c_str(), FILE_READ_DATA | READ_CONTROL, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file.handle == INVALID_HANDLE_VALUE) return false;
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file.handle, &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
            !PrivateFile(file.handle)) return false;
        std::string text(67, '\0');
        DWORD count = 0;
        if (!ReadFile(file.handle, text.data(), static_cast<DWORD>(text.size()), &count, nullptr) || count > 66) {
            SecureZeroMemory(text.data(), text.size()); return false;
        }
        text.resize(static_cast<size_t>(count));
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n')) text.pop_back();
        const bool ok = Unhex(text, bytes.data(), bytes.size());
        if (!text.empty()) SecureZeroMemory(text.data(), text.size());
        return ok;
    }
};
bool Proof(const Secret& secret, const std::vector<uint8_t>& challenge, std::array<uint8_t, 32>& proof) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        return false;
    bool ok = BCryptCreateHash(algorithm, &hash, nullptr, 0,
        const_cast<PUCHAR>(secret.bytes.data()), static_cast<ULONG>(secret.bytes.size()), 0) >= 0;
    static const uint8_t domain[] = "VEH-REMOTE-CLIENT-v1";
    if (ok) ok = BCryptHashData(hash, const_cast<PUCHAR>(domain), sizeof(domain) - 1, 0) >= 0 &&
        BCryptHashData(hash, const_cast<PUCHAR>(challenge.data()), static_cast<ULONG>(challenge.size()), 0) >= 0 &&
        BCryptFinishHash(hash, proof.data(), static_cast<ULONG>(proof.size()), 0) >= 0;
    if (hash) BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}
struct ControlHeader { uint32_t magic, version, type, size; };
}

struct Channel::Impl {
    std::atomic<SOCKET> socket{INVALID_SOCKET};
    CredHandle credentials{};
    CtxtHandle context{};
    bool haveCredentials = false, haveContext = false;
    SecPkgContext_StreamSizes sizes{};
    std::vector<uint8_t> encrypted, plain;
    size_t plainOffset = 0;
    std::timed_mutex readMutex, writeMutex;
    Impl() { SecInvalidateHandle(&credentials); SecInvalidateHandle(&context); }
    void ResetSecurity() {
        if (haveContext) DeleteSecurityContext(&context);
        if (haveCredentials) FreeCredentialsHandle(&credentials);
        haveContext = false; haveCredentials = false;
        SecInvalidateHandle(&context); SecInvalidateHandle(&credentials);
    }

    bool Handshake(bool server, const std::string& host, const std::string& fingerprint, int timeoutMs) {
        Budget budget(timeoutMs);
        if (!budget.Remaining()) return false;
        bool completed = false;
        struct Cleanup {
            Impl& impl; bool& completed;
            ~Cleanup() { if (!completed) impl.ResetSecurity(); }
        } cleanup{*this, completed};
        const auto deadline = budget.deadline;
        std::array<uint8_t, 32> pin{};
        if (!Unhex(fingerprint, pin.data(), pin.size())) return false;
        PCCERT_CONTEXT certificate = server ? FindCertificate(pin) : nullptr;
        if (server && !certificate) return false;
        SCHANNEL_CRED options{};
        options.dwVersion = SCHANNEL_CRED_VERSION;
        options.grbitEnabledProtocols = server ? SP_PROT_TLS1_2_SERVER : SP_PROT_TLS1_2_CLIENT;
        options.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;
        if (!server) options.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
        if (certificate) { options.cCreds = 1; options.paCred = &certificate; }
        TimeStamp expiry{};
        auto status = AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W),
            server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr, &options, nullptr, nullptr,
            &credentials, &expiry);
        if (certificate) CertFreeCertificateContext(certificate);
        if (status != SEC_E_OK) return false;
        haveCredentials = true;
        if (!budget.Remaining()) return false;
        bool first = true, needRead = server;
        const std::wstring wideHost(host.begin(), host.end());
        for (;;) {
            if (!budget.Remaining()) return false;
            if (needRead && !RawRead(socket, encrypted, deadline)) return false;
            SecBuffer input[2]{{static_cast<ULONG>(encrypted.size()), SECBUFFER_TOKEN, encrypted.data()},
                {0, SECBUFFER_EMPTY, nullptr}};
            SecBufferDesc inputDesc{SECBUFFER_VERSION, 2, input};
            SecBuffer output{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc outputDesc{SECBUFFER_VERSION, 1, &output};
            ULONG attributes = 0;
            if (server) {
                status = AcceptSecurityContext(&credentials, first ? nullptr : &context, &inputDesc,
                    ASC_REQ_STREAM | ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT |
                    ASC_REQ_ALLOCATE_MEMORY, SECURITY_NATIVE_DREP, &context, &outputDesc, &attributes, &expiry);
            } else {
                status = InitializeSecurityContextW(&credentials, first ? nullptr : &context,
                    const_cast<LPWSTR>(wideHost.c_str()), ISC_REQ_STREAM | ISC_REQ_CONFIDENTIALITY |
                    ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_ALLOCATE_MEMORY |
                    ISC_REQ_MANUAL_CRED_VALIDATION, 0, SECURITY_NATIVE_DREP,
                    first ? nullptr : &inputDesc, 0, &context, &outputDesc, &attributes, &expiry);
            }
            // SSPI may allocate a context before sending its handshake token.
            // Track it before any write/error return so failed handshakes release it.
            haveContext = SecIsValidHandle(&context) != FALSE;
            if (output.pvBuffer) {
                const bool sent = !output.cbBuffer || RawWrite(socket, static_cast<uint8_t*>(output.pvBuffer),
                    output.cbBuffer, deadline);
                FreeContextBuffer(output.pvBuffer);
                if (!sent) return false;
            }
            if (status == SEC_E_INCOMPLETE_MESSAGE) { needRead = true; continue; }
            if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) return false;
            haveContext = true;
            if (input[1].BufferType == SECBUFFER_EXTRA) {
                std::vector<uint8_t> rest(encrypted.end() - input[1].cbBuffer, encrypted.end());
                encrypted.swap(rest);
            } else encrypted.clear();
            first = false;
            if (status == SEC_E_OK) break;
            needRead = encrypted.empty();
        }
        if (!server) {
            PCCERT_CONTEXT peer = nullptr;
            if (QueryContextAttributesW(&context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer) != SEC_E_OK) return false;
            const bool valid = Fingerprint(peer, pin);
            CertFreeCertificateContext(peer);
            if (!valid) return false;
        }
        completed = QueryContextAttributesW(&context, SECPKG_ATTR_STREAM_SIZES, &sizes) == SEC_E_OK &&
            budget.Remaining() > 0;
        return completed;
    }
};
Channel::Channel() : impl_(std::make_unique<Impl>()) {}
Channel::~Channel() { Close(); }
void Channel::Cancel() { if (impl_->socket != INVALID_SOCKET) shutdown(impl_->socket, SD_BOTH); }
void Channel::Close() {
    Cancel();
    const auto socket = impl_->socket.exchange(INVALID_SOCKET);
    if (socket != INVALID_SOCKET) closesocket(socket);
    impl_->ResetSecurity();
    impl_->encrypted.clear(); impl_->plain.clear(); impl_->plainOffset = 0; impl_->sizes = {};
}
bool Channel::Connect(const std::string& host, uint16_t port, const std::string& pin, int timeoutMs) {
    if (!Startup() || timeoutMs <= 0 || port == 0) return false;
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* addresses = nullptr;
    // Profiles use numeric addresses: DNS cannot consume an unbounded connection deadline.
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &addresses)) return false;
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    for (auto* entry = addresses; entry; entry = entry->ai_next) {
        SOCKET socket = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (socket == INVALID_SOCKET) continue;
        u_long nonblocking = 1; ioctlsocket(socket, FIONBIO, &nonblocking);
        int connected = connect(socket, entry->ai_addr, static_cast<int>(entry->ai_addrlen));
        if (connected == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK && WaitSocket(socket, true, deadline)) {
            int error = 0, size = sizeof(error);
            if (!getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) && !error) connected = 0;
        }
        if (!connected) { impl_->socket = socket; break; }
        closesocket(socket);
    }
    freeaddrinfo(addresses);
    const auto now = GetTickCount64();
    if (impl_->socket == INVALID_SOCKET || now >= deadline) return false;
    const BOOL noDelay = TRUE; setsockopt(impl_->socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    return impl_->Handshake(false, host, pin, static_cast<int>(deadline - now));
}
bool Channel::Accept(uintptr_t socket, const std::string& pin, int timeoutMs) {
    impl_->socket = static_cast<SOCKET>(socket);
    return Startup() && impl_->Handshake(true, "", pin, timeoutMs);
}
bool Channel::Read(void* destination, size_t size, int timeoutMs, HANDLE stop) {
    if (timeoutMs <= 0 || (!destination && size)) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    Budget budget(timeoutMs);
    std::unique_lock<std::timed_mutex> lock(impl_->readMutex, std::defer_lock);
    if (!lock.try_lock_for(std::chrono::milliseconds(budget.Remaining()))) { SetLastError(WAIT_TIMEOUT); return false; }
    auto* output = static_cast<uint8_t*>(destination);
    const auto deadline = budget.deadline;
    size_t copied = 0;
    while (copied < size) {
        if (timeoutMs <= 0 || GetTickCount64() >= deadline ||
            (stop && WaitForSingleObject(stop, 0) == WAIT_OBJECT_0)) { SetLastError(WAIT_TIMEOUT); break; }
        if (impl_->plainOffset < impl_->plain.size()) {
            size_t count = std::min(size - copied, impl_->plain.size() - impl_->plainOffset);
            memcpy(output + copied, impl_->plain.data() + impl_->plainOffset, count);
            impl_->plainOffset += count; copied += count; continue;
        }
        impl_->plain.clear(); impl_->plainOffset = 0;
        if (impl_->encrypted.empty() && !RawRead(impl_->socket, impl_->encrypted, deadline, stop)) break;
        SecBuffer buffers[4]{{static_cast<ULONG>(impl_->encrypted.size()), SECBUFFER_DATA, impl_->encrypted.data()},
            {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}, {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc description{SECBUFFER_VERSION, 4, buffers};
        auto status = DecryptMessage(&impl_->context, &description, 0, nullptr);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            if (!RawRead(impl_->socket, impl_->encrypted, deadline, stop)) break;
            continue;
        }
        // Renegotiation/re-authentication is not accepted on an established job channel.
        if (status != SEC_E_OK) { SetLastError(ERROR_BROKEN_PIPE); break; }
        std::vector<uint8_t> extra;
        for (const auto& buffer : buffers) {
            if (buffer.BufferType == SECBUFFER_DATA) {
                auto* begin = static_cast<uint8_t*>(buffer.pvBuffer);
                impl_->plain.insert(impl_->plain.end(), begin, begin + buffer.cbBuffer);
            } else if (buffer.BufferType == SECBUFFER_EXTRA)
                extra.assign(impl_->encrypted.end() - buffer.cbBuffer, impl_->encrypted.end());
        }
        impl_->encrypted.swap(extra);
    }
    if (copied == size) return true;
    // A partial IPC frame must never become the header of another request.
    if (copied) { SetLastError(ERROR_INVALID_DATA); Cancel(); }
    return false;
}
bool Channel::Write(const void* source, size_t size, int timeoutMs) {
    if (timeoutMs <= 0 || (!source && size)) { SetLastError(ERROR_INVALID_PARAMETER); return false; }
    Budget budget(timeoutMs);
    std::unique_lock<std::timed_mutex> lock(impl_->writeMutex, std::defer_lock);
    if (!lock.try_lock_for(std::chrono::milliseconds(budget.Remaining()))) { SetLastError(WAIT_TIMEOUT); return false; }
    const auto deadline = budget.deadline;
    auto* input = static_cast<const uint8_t*>(source);
    while (size) {
        const auto count = std::min<size_t>(size, impl_->sizes.cbMaximumMessage);
        if (!count || timeoutMs <= 0) { Cancel(); return false; }
        std::vector<uint8_t> record(impl_->sizes.cbHeader + count + impl_->sizes.cbTrailer);
        memcpy(record.data() + impl_->sizes.cbHeader, input, count);
        SecBuffer buffers[4]{{impl_->sizes.cbHeader, SECBUFFER_STREAM_HEADER, record.data()},
            {static_cast<ULONG>(count), SECBUFFER_DATA, record.data() + impl_->sizes.cbHeader},
            {impl_->sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, record.data() + impl_->sizes.cbHeader + count},
            {0, SECBUFFER_EMPTY, nullptr}};
        SecBufferDesc description{SECBUFFER_VERSION, 4, buffers};
        if (EncryptMessage(&impl_->context, 0, &description, 0) != SEC_E_OK ||
            !RawWrite(impl_->socket, record.data(), buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer, deadline)) {
            Cancel(); return false;
        }
        input += count; size -= count;
    }
    return true;
}
bool WriteControl(Channel& channel, Control type, const void* data, uint32_t size, int timeoutMs) {
    Budget budget(timeoutMs);
    if (size > 65536 || (size && !data) || !budget.Remaining()) return false;
    ControlHeader header{kMagic, kVersion, static_cast<uint32_t>(type), size};
    const bool ok = channel.Write(&header, sizeof(header), budget.Remaining()) &&
        (!size || channel.Write(data, size, budget.Remaining())) && budget.Remaining() > 0;
    if (!ok) channel.Cancel();
    return ok;
}
bool ReadControl(Channel& channel, Control expected, std::vector<uint8_t>& data, int timeoutMs) {
    Budget budget(timeoutMs);
    data.clear();
    if (!budget.Remaining()) return false;
    ControlHeader header{};
    if (!channel.Read(&header, sizeof(header), budget.Remaining()) || header.magic != kMagic ||
        header.version != kVersion || header.type != static_cast<uint32_t>(expected) || header.size > 65536) {
        channel.Cancel(); return false;
    }
    data.resize(header.size);
    const bool ok = (data.empty() || channel.Read(data.data(), data.size(), budget.Remaining())) &&
        budget.Remaining() > 0;
    if (!ok) { data.clear(); channel.Cancel(); }
    return ok;
}
bool AuthenticateClient(Channel& channel, const std::wstring& tokenFile, int timeoutMs) {
    Budget budget(timeoutMs);
    if (!budget.Remaining()) return false;
    Secret secret;
    std::vector<uint8_t> nonce, accepted;
    std::array<uint8_t, 32> proof{};
    const bool ok = secret.Load(tokenFile) && budget.Remaining() > 0 &&
        ReadControl(channel, Control::Challenge, nonce, budget.Remaining()) && nonce.size() == 32 &&
        Proof(secret, nonce, proof) &&
        WriteControl(channel, Control::Proof, proof.data(), static_cast<uint32_t>(proof.size()), budget.Remaining()) &&
        ReadControl(channel, Control::Authenticated, accepted, budget.Remaining()) && accepted.empty() &&
        budget.Remaining() > 0;
    SecureZeroMemory(proof.data(), proof.size());
    if (!ok) channel.Cancel();
    return ok;
}
bool AuthenticateServer(Channel& channel, const std::wstring& tokenFile, int timeoutMs) {
    Budget budget(timeoutMs);
    if (!budget.Remaining()) return false;
    Secret secret;
    std::vector<uint8_t> nonce(32), received;
    std::array<uint8_t, 32> expected{};
    const bool ok = secret.Load(tokenFile) && budget.Remaining() > 0 &&
        BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 &&
        Proof(secret, nonce, expected) &&
        WriteControl(channel, Control::Challenge, nonce.data(), static_cast<uint32_t>(nonce.size()), budget.Remaining()) &&
        ReadControl(channel, Control::Proof, received, budget.Remaining()) && received.size() == expected.size() &&
        Equal(received.data(), expected.data(), expected.size()) &&
        WriteControl(channel, Control::Authenticated, nullptr, 0, budget.Remaining()) && budget.Remaining() > 0;
    SecureZeroMemory(expected.data(), expected.size());
    if (!received.empty()) SecureZeroMemory(received.data(), received.size());
    if (!ok) channel.Cancel();
    return ok;
}
std::string RandomId() {
    uint8_t bytes[32]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return {};
    const char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
uintptr_t Listen(const std::string& address, uint16_t port) {
    if (!Startup() || !port) return static_cast<uintptr_t>(INVALID_SOCKET);
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(address.c_str(), std::to_string(port).c_str(), &hints, &addresses)) return static_cast<uintptr_t>(INVALID_SOCKET);
    SOCKET listener = INVALID_SOCKET;
    for (auto* entry = addresses; entry; entry = entry->ai_next) {
        listener = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (listener == INVALID_SOCKET) continue;
        const BOOL exclusive = TRUE;
        setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
        if (!bind(listener, entry->ai_addr, static_cast<int>(entry->ai_addrlen)) && !listen(listener, 8)) break;
        closesocket(listener); listener = INVALID_SOCKET;
    }
    freeaddrinfo(addresses);
    return static_cast<uintptr_t>(listener);
}
uintptr_t AcceptSocket(uintptr_t listener, std::string& address) {
    sockaddr_storage peer{}; int size = sizeof(peer);
    const SOCKET accepted = accept(static_cast<SOCKET>(listener), reinterpret_cast<sockaddr*>(&peer), &size);
    if (accepted == INVALID_SOCKET) return static_cast<uintptr_t>(INVALID_SOCKET);
    char host[NI_MAXHOST]{};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&peer), size, host, sizeof(host), nullptr, 0, NI_NUMERICHOST)) {
        closesocket(accepted); return static_cast<uintptr_t>(INVALID_SOCKET);
    }
    address = host;
    u_long nonblocking = 1; ioctlsocket(accepted, FIONBIO, &nonblocking);
    const BOOL noDelay = TRUE;
    setsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    return static_cast<uintptr_t>(accepted);
}
void CloseSocket(uintptr_t socket) { if (socket != static_cast<uintptr_t>(INVALID_SOCKET)) closesocket(static_cast<SOCKET>(socket)); }
} // namespace veh::remote
