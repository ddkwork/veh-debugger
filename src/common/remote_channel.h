#pragma once
#include <windows.h>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace veh::remote {
// TLS is the byte transport; VEH IPC framing is unchanged inside it.
class Channel {
public:
    Channel();
    ~Channel();
    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;
    bool Connect(const std::string& host, uint16_t port, const std::string& certificateSha256, int timeoutMs);
    bool Accept(uintptr_t socket, const std::string& certificateSha256, int timeoutMs);
    bool Read(void* data, size_t size, int timeoutMs, HANDLE stop = nullptr);
    bool Write(const void* data, size_t size, int timeoutMs);
    void Cancel();
    void Close();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

constexpr uint32_t kMagic = 0x52484556; // VEHR, little endian
constexpr uint32_t kVersion = 1;
enum class Control : uint32_t { Challenge = 1, Proof = 2, Authenticated = 3, OpenWork = 4, Work = 5 };
bool WriteControl(Channel& channel, Control type, const void* data, uint32_t size, int timeoutMs);
bool ReadControl(Channel& channel, Control expected, std::vector<uint8_t>& data, int timeoutMs);
bool AuthenticateClient(Channel& channel, const std::wstring& tokenFile, int timeoutMs);
bool AuthenticateServer(Channel& channel, const std::wstring& tokenFile, int timeoutMs);
std::string RandomId();
uintptr_t Listen(const std::string& address, uint16_t port);
uintptr_t AcceptSocket(uintptr_t listener, std::string& address);
void CloseSocket(uintptr_t socket);
} // namespace veh::remote
