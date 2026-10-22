// Host-only protocol fixture. Never injected into or installed in a guest.
#include <windows.h>
#include <string>
#include <vector>
#include <cstring>
#include "ipc_protocol.h"

bool transfer(HANDLE pipe, bool writing, void* bytes, DWORD size) {
    auto* next = static_cast<unsigned char*>(bytes);
    while (size) {
        DWORD done = 0;
        const BOOL ok = writing ? WriteFile(pipe, next, size, &done, nullptr) : ReadFile(pipe, next, size, &done, nullptr);
        if (!ok || !done) return false;
        next += done; size -= done;
    }
    return true;
}
bool send(HANDLE pipe, uint32_t command, const void* bytes, uint32_t size) {
    veh::IpcHeader header{command, size};
    return transfer(pipe, true, &header, sizeof(header)) &&
        (!size || transfer(pipe, true, const_cast<void*>(bytes), size));
}
template<class T> bool reply(HANDLE pipe, uint32_t command, const T& value) { return send(pipe, command, &value, sizeof(value)); }

int wmain(int argc, wchar_t** argv) {
    std::wstring name, mode;
    uint32_t pid = 0;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::wstring option = argv[i];
        if (option == L"--pid") pid = std::stoul(argv[i + 1]);
        else if (option == L"--pipe") name = argv[i + 1];
        else if (option == L"--metadata") mode = argv[i + 1];
    }
    if (!pid || name.empty()) return 2;
    HANDLE pipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return 3;
    if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(pipe); return 4; }
    send(pipe, static_cast<uint32_t>(veh::IpcEvent::Ready), nullptr, 0);
    for (;;) {
        veh::IpcHeader header{};
        if (!transfer(pipe, false, &header, sizeof(header)) || header.payloadSize > 65536) break;
        std::vector<unsigned char> bytes(header.payloadSize);
        if (!bytes.empty() && !transfer(pipe, false, bytes.data(), header.payloadSize)) break;
        const auto command = static_cast<veh::IpcCommand>(header.command);
        if (command == veh::IpcCommand::GetCapabilities) {
            veh::GetCapabilitiesResponse caps{};
            caps.status = veh::IpcStatus::Ok; caps.backend = veh::IpcBackend::Hypervisor;
            caps.flags = veh::kCapNoTargetFootprint | (mode == L"host-cap" ? 0 : veh::kCapGuestTarget);
            for (auto op : {veh::IpcCommand::GetCapabilities, veh::IpcCommand::GetTargetInfo, veh::IpcCommand::GetThreads,
                            veh::IpcCommand::ReadMemory, veh::IpcCommand::Heartbeat, veh::IpcCommand::Detach})
                veh::SetCommandSupported(caps.commands, op);
            strcpy_s(caps.name, "synthetic-guest");
            if (!reply(pipe, header.command, caps)) break;
        } else if (command == veh::IpcCommand::GetTargetInfo) {
            veh::GetTargetInfoResponse info{veh::IpcStatus::Ok, veh::IpcTargetScope::Guest, pid, 32};
            if (mode == L"wrong-pid") ++info.pid;
            if (mode == L"bad-width") info.addressBits = 16;
            if (mode == L"wrong-scope") info.scope = veh::IpcTargetScope::Host;
            if (mode == L"not-found") { info = {}; info.status = veh::IpcStatus::NotFound; }
            if (!send(pipe, header.command, &info, mode == L"truncated" ? 8 : sizeof(info))) break;
        } else if (command == veh::IpcCommand::GetThreads) {
            struct { veh::GetThreadsResponse header; veh::ThreadInfo thread; } threads{};
            threads.header.status = veh::IpcStatus::Ok; threads.header.count = 1; threads.thread.id = 77;
            if (!reply(pipe, header.command, threads)) break;
        } else if (command == veh::IpcCommand::ReadMemory && bytes.size() == sizeof(veh::ReadMemoryRequest)) {
            veh::ReadMemoryRequest request{}; memcpy(&request, bytes.data(), sizeof(request));
            if (request.size > 4096) { reply(pipe, header.command, veh::IpcStatus::InvalidArgs); continue; }
            std::vector<unsigned char> response(sizeof(veh::IpcStatus) + request.size, 0x90);
            const auto status = veh::IpcStatus::Ok; memcpy(response.data(), &status, sizeof(status));
            // x86 INC EDX; RET, versus the x64 REX prefix. Tests metadata bitness.
            if (request.size) response[sizeof(status)] = 0x42;
            if (request.size > 1) response[sizeof(status) + 1] = 0xc3;
            if (!send(pipe, header.command, response.data(), static_cast<uint32_t>(response.size()))) break;
        } else if (command == veh::IpcCommand::Heartbeat) {
            if (!send(pipe, static_cast<uint32_t>(veh::IpcEvent::HeartbeatAck), nullptr, 0)) break;
        } else if (command == veh::IpcCommand::Detach) {
            reply(pipe, header.command, veh::IpcStatus::Ok); break;
        } else if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break;
    }
    CloseHandle(pipe);
    return 0;
}
