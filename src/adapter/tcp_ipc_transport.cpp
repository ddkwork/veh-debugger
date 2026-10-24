#include "tcp_ipc_transport.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <utility>

namespace veh {
TcpIpcTransport::TcpIpcTransport(RemoteEndpoint endpoint, std::string openRequest)
    : endpoint_(std::move(endpoint)), openRequest_(std::move(openRequest)) {}

bool TcpIpcTransport::Connect(uint32_t, int timeoutMs) {
    error_ = "Remote connection or authentication failed";
    openOutcome_ = RemoteOpenOutcome::NotSent;
    const int budget = std::clamp(std::min(timeoutMs, endpoint_.timeoutMs), 100, 30000);
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(budget);
    auto remaining = [&]() -> int {
        const auto now = GetTickCount64();
        return now < deadline ? static_cast<int>(deadline - now) : 0;
    };
    if (openRequest_.size() > 65536 || !channel_.Connect(endpoint_.address, endpoint_.port,
        endpoint_.certificateSha256, remaining()) ||
        !remote::AuthenticateClient(channel_, endpoint_.tokenFile, remaining())) {
        channel_.Close(); return false;
    }
    // A failed write can still have delivered the complete OpenWork request.
    openOutcome_ = RemoteOpenOutcome::Unknown;
    error_ = "Remote work open result unknown; check resident work before repeating launch";
    if (!remote::WriteControl(channel_, remote::Control::OpenWork, openRequest_.data(),
            static_cast<uint32_t>(openRequest_.size()), remaining())) {
        channel_.Close(); return false;
    }
    std::vector<uint8_t> bytes;
    if (!remote::ReadControl(channel_, remote::Control::Work, bytes, remaining())) {
        error_ = "Remote work open result unknown; check resident work before repeating launch";
        channel_.Close(); return false;
    }
    try {
        auto reply = nlohmann::json::parse(bytes);
        if (!reply.at("success").is_boolean()) throw std::invalid_argument("metadata");
        if (!reply.at("success").get<bool>()) {
            // Validate the complete rejection before clearing duplicate-launch protection.
            const auto code = reply.at("code").get<std::string>();
            if (code != "unsupported" && code != "busy" && code != "expired" &&
                code != "invalid" && code != "unavailable") throw std::invalid_argument("metadata");
            // Older/ambiguous replies must not clear duplicate-launch protection.
            if (reply.contains("outcome_unknown") && reply.at("outcome_unknown").is_boolean() &&
                !reply.at("outcome_unknown").get<bool>()) openOutcome_ = RemoteOpenOutcome::Rejected;
            // Server sends fixed reason codes, never exception text or credentials.
            if (code == "unsupported") error_ = "Remote backend does not implement this operation";
            else if (code == "busy") error_ = "Remote work already has an active connection";
            else if (code == "expired") error_ = "Remote work expired or requires a fresh attachment";
            else error_ = "Remote work could not be opened";
            channel_.Close(); return false;
        }
        work_.id = reply.at("work_id").get<std::string>();
        work_.scope = reply.at("target_scope").get<std::string>();
        for (const char* key : {"pid", "address_bits"}) {
            if (!reply.at(key).is_number_unsigned() || reply.at(key).get<uint64_t>() > UINT32_MAX)
                throw std::invalid_argument("metadata");
        }
        if (!reply.at("outcome_unknown").is_boolean()) throw std::invalid_argument("metadata");
        work_.pid = reply.at("pid").get<uint32_t>();
        work_.addressBits = reply.at("address_bits").get<uint32_t>();
        work_.outcomeUnknown = reply.at("outcome_unknown").get<bool>();
        if (!remaining() || work_.id.size() != 64 || !std::all_of(work_.id.begin(), work_.id.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }) || (work_.scope != "host" && work_.scope != "guest" && work_.scope != "vm") ||
            (work_.scope == "vm" ? work_.pid != 0 || work_.addressBits != 0 :
                !work_.pid || (work_.addressBits != 32 && work_.addressBits != 64))) {
            channel_.Close(); return false;
        }
    } catch (...) { channel_.Close(); return false; }
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) { channel_.Close(); return false; }
    { std::lock_guard<std::mutex> lock(readyMutex_); readyReceived_ = false; }
    lastRecvTime_ = GetTickCount64();
    connected_ = true;
    openOutcome_ = RemoteOpenOutcome::Opened;
    error_.clear();
    return true;
}
void TcpIpcTransport::Disconnect() {
    channel_.Cancel();
    PipeClient::Disconnect();
    channel_.Close();
}
bool TcpIpcTransport::AsyncReadExact(void* data, DWORD size, DWORD timeoutMs) {
    return channel_.Read(data, size, static_cast<int>(timeoutMs), stopEvent_);
}
bool TcpIpcTransport::AsyncWriteExact(const void* data, DWORD size, DWORD timeoutMs) {
    return channel_.Write(data, size, static_cast<int>(timeoutMs));
}
void TcpIpcTransport::CancelPendingIo() {
    // StopEventListener signals stopEvent_; Channel::Read checks it every 100ms.
    // Preserve the write side so DebugSession can send its final Detach frame.
}
} // namespace veh
