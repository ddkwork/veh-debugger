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
    const bool vmMode=mode.rfind(L"vm",0)==0;uint32_t vmState=2;
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
            if(vmMode) {
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::ControlVirtualMachine);
                veh::SetCommandSupported(caps.commands,veh::IpcCommand::TraceVirtualCpu);
            }
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
        } else if(vmMode&&command==veh::IpcCommand::ControlVirtualMachine&&bytes.size()==sizeof(veh::ControlVirtualMachineRequest)) {
            veh::ControlVirtualMachineRequest request{};memcpy(&request,bytes.data(),sizeof(request));
            veh::ControlVirtualMachineResponse response{veh::IpcStatus::Ok,veh::VirtualMachineState::Paused};
            if(request.reserved||static_cast<uint32_t>(request.action)>2)response.status=veh::IpcStatus::InvalidArgs;
            else if(request.action==veh::VirtualMachineAction::Pause)vmState=2;
            else if(request.action==veh::VirtualMachineAction::Resume)vmState=1;
            response.state=static_cast<veh::VirtualMachineState>(vmState);
            if(!reply(pipe,header.command,response))break;
        } else if(vmMode&&command==veh::IpcCommand::TraceVirtualCpu&&bytes.size()==sizeof(veh::TraceVirtualCpuRequest)) {
            veh::TraceVirtualCpuRequest request{};memcpy(&request,bytes.data(),sizeof(request));
            const uint32_t count=request.maxInstructions<64?request.maxInstructions:64;
            veh::TraceVirtualCpuResponse response{veh::IpcStatus::Ok,1,request.maxInstructions,
                request.maxInstructions-count,123456,count,1,1,0};
            if(mode==L"vm-failure"){response.status=veh::IpcStatus::Error;response.completed=2;response.count=2;response.lost=0;response.stopReason=4;response.executionStatus=23;}
            if(mode==L"vm-bad-trace")response.completed=0;
            std::vector<unsigned char> data(sizeof(response)+response.count*sizeof(veh::VirtualCpuInstructionRecord));
            memcpy(data.data(),&response,sizeof(response));
            for(uint32_t i=0;i<response.count;++i) {
                const veh::VirtualCpuInstructionRecord record{static_cast<uint64_t>(i)+1,UINT64_C(9007199254740993)+i,
                    UINT64_C(0x1000),UINT64_C(0x900f),UINT64_C(0x900f),UINT64_C(0x11223345),UINT64_C(0x11223345),
                    0,0,UINT64_C(0x8000),2,request.cpu,0};
                memcpy(data.data()+sizeof(response)+static_cast<size_t>(i)*sizeof(record),&record,sizeof(record));
            }
            if(!send(pipe,header.command,data.data(),mode==L"vm-truncated"?8:static_cast<uint32_t>(data.size())))break;
        } else if (command == veh::IpcCommand::Heartbeat) {
            if (!send(pipe, static_cast<uint32_t>(veh::IpcEvent::HeartbeatAck), nullptr, 0)) break;
        } else if (command == veh::IpcCommand::Detach) {
            reply(pipe, header.command, veh::IpcStatus::Ok); break;
        } else if (!reply(pipe, header.command, veh::IpcStatus::Unsupported)) break;
    }
    CloseHandle(pipe);
    return 0;
}
