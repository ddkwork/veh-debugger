#include "work_owner.h"
#include <algorithm>
#include <filesystem>
#include <map>
#include <cstring>

namespace veh::remote {
namespace {
std::wstring Wide(const std::string& value) {
    if (value.find('\0') != std::string::npos) throw std::invalid_argument("string");
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!value.empty() && !count) throw std::invalid_argument("utf8");
    std::wstring result(count, L'\0');
    if (count) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count);
    return result;
}
std::wstring Quote(const std::wstring& value) {
    std::wstring result = L"\""; size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        result.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0; result += c;
    }
    result.append(slashes * 2, L'\\'); result += L'"';
    return result;
}
struct CaseLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const { return _wcsicmp(a.c_str(), b.c_str()) < 0; }
};
std::vector<wchar_t> Environment(const Json& launch) {
    std::map<std::wstring, std::wstring, CaseLess> values;
    LPWCH inherited = GetEnvironmentStringsW();
    if (!inherited) throw std::runtime_error("environment");
    for (const wchar_t* p = inherited; *p; p += wcslen(p) + 1) {
        std::wstring item(p); const auto at = item.find(L'=', 1);
        if (at != std::wstring::npos) values[item.substr(0, at)] = item.substr(at + 1);
    }
    FreeEnvironmentStringsW(inherited);
    const auto extra = launch.value("env", Json::array());
    if (!extra.is_array() || extra.size() > 128) throw std::invalid_argument("environment");
    for (const auto& entry : extra) {
        const auto item = Wide(entry.get<std::string>());
        const auto at = item.find(L'=');
        if (!at || at == std::wstring::npos) throw std::invalid_argument("environment");
        values[item.substr(0, at)] = item.substr(at + 1);
    }
    if (launch.value("runAsInvoker", false)) values[L"__COMPAT_LAYER"] = L"RunAsInvoker";
    std::vector<wchar_t> block;
    for (const auto& entry : values) {
        const auto item = entry.first + L"=" + entry.second;
        block.insert(block.end(), item.begin(), item.end()); block.push_back(0);
        if (block.size() > 32766) throw std::invalid_argument("environment");
    }
    block.push_back(0);
    if (block.size() == 1) block.push_back(0);
    return block;
}
uint32_t Width(HANDLE process) {
    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64)) return 0;
    SYSTEM_INFO info{}; GetNativeSystemInfo(&info);
    const bool native64 = info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
    return wow64 || !native64 ? 32 : 64;
}
template<class T> std::vector<uint8_t> Bytes(const T& value) {
    std::vector<uint8_t> data(sizeof(value)); memcpy(data.data(), &value, sizeof(value)); return data;
}
}
std::shared_ptr<WorkOwner> WorkOwner::Open(const BackendProfile& profile, const Json& request, std::string& code) {
    auto owner = std::shared_ptr<WorkOwner>(new WorkOwner);
    try {
        if (!owner->Initialize(profile, request, code)) { owner->Stop(); return {}; }
    } catch (...) { code = "invalid"; owner->Stop(); return {}; }
    owner->worker_ = std::thread([owner] { owner->Worker(); });
    return owner;
}
bool WorkOwner::Initialize(const BackendProfile& profile, const Json& request, std::string& code) {
    code = "unavailable";
    const auto started = GetTickCount64();
    scope_ = request.at("target_scope").get<std::string>();
    backendName_ = request.at("backend").get<std::string>();
    if (scope_ != profile.scope) { code = "invalid"; return false; }
    const auto operation = request.at("operation").get<std::string>();
    if (operation != "attach" && operation != "launch") { code = "invalid"; return false; }
    if (operation == "launch" && (scope_ != "host" || !profile.allowLaunch)) { code = "unsupported"; return false; }
    const auto pidValue = request.at("pid");
    if (!pidValue.is_number_unsigned() || pidValue.get<uint64_t>() > UINT32_MAX) { code = "invalid"; return false; }
    pid_ = pidValue.get<uint32_t>();
    if (operation == "attach" && (scope_ == "vm" ? pid_ != 0 : pid_ == 0)) { code = "invalid"; return false; }
    if (operation == "launch" && pid_) { code = "invalid"; return false; }
    id_ = RandomId();
    if (id_.empty()) return false;
    job_ = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (scope_ != "host") limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if (!job_ || !SetInformationJobObject(job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) return false;
    if (operation == "launch") {
        requestId_ = request.at("request_id").get<std::string>();
        if (requestId_.size() != 64) { code = "invalid"; return false; }
        const auto& launch = request.at("launch");
        const auto program = Wide(launch.at("program").get<std::string>());
        if (program.empty() || program.size() > 16000) { code = "invalid"; return false; }
        auto command = Quote(program);
        const auto args = launch.value("args", Json::array());
        if (!args.is_array() || args.size() > 128) { code = "invalid"; return false; }
        for (const auto& value : args) {
            command += L" " + Quote(Wide(value.get<std::string>()));
            if (command.size() > 32766) { code = "invalid"; return false; }
        }
        const auto cwd = Wide(launch.value("cwd", std::string()));
        auto environment = Environment(launch);
        STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{};
        if (!CreateProcessW(program.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, environment.data(),
            cwd.empty() ? nullptr : cwd.c_str(), &si, &pi)) return false;
        targetProcess_ = pi.hProcess; primaryThread_ = pi.hThread;
        pid_ = pi.dwProcessId; mainThreadId_ = pi.dwThreadId;
        if (!AssignProcessToJobObject(job_, targetProcess_)) {
            TerminateProcess(targetProcess_, 1); WaitForSingleObject(targetProcess_, 2000); return false;
        }
    } else if (scope_ == "host") {
        targetProcess_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid_);
        if (!targetProcess_ || WaitForSingleObject(targetProcess_, 0) != WAIT_TIMEOUT) return false;
    }
    if (scope_ == "host") { addressBits_ = Width(targetProcess_); if (!addressBits_) return false; }
    const auto pipe = L"\\\\.\\pipe\\veh-resident-" + Wide(id_);
    auto command = Quote(profile.executable);
    if (scope_ != "vm") command += L" --pid " + std::to_wstring(pid_);
    command += L" --pipe " + Quote(pipe);
    for (const auto& value : profile.args) command += L" " + Quote(value);
    if (command.size() > 32766) { code = "invalid"; return false; }
    STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{};
    if (!CreateProcessW(profile.executable.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) return false;
    agentProcess_ = pi.hProcess;
    // Guest/VM bridge children silently break away: the bridge belongs to this
    // work, but persistent VMM descendants must not inherit its kill-on-close job.
    const bool assigned = AssignProcessToJobObject(job_, agentProcess_) != FALSE;
    if (assigned) ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    if (!assigned) return false;
    backend_ = std::make_unique<PipeClient>(pipe);
    if (!backend_->Connect(pid_, 5000) || backend_->PeerProcessId() != pi.dwProcessId) return false;
    backend_->StartEventListener([this](uint32_t command, const uint8_t* data, uint32_t size) { OnEvent(command, data, size); });
    if (!backend_->WaitForReady(3000)) return false;
    std::vector<uint8_t> bytes;
    if (!backend_->SendAndReceive(IpcCommand::GetCapabilities, nullptr, 0, bytes) ||
        bytes.size() < sizeof(GetCapabilitiesResponse)) return false;
    GetCapabilitiesResponse caps{}; memcpy(&caps, bytes.data(), sizeof(caps));
    if (caps.status != IpcStatus::Ok ||
        ((caps.flags & kCapGuestTarget) != 0) != (scope_ == "guest") ||
        ((caps.flags & kCapVirtualMachineTarget) != 0) != (scope_ == "vm")) return false;
    if (scope_ != "host") {
        if (!IsCommandSupported(caps.commands, IpcCommand::GetTargetInfo) ||
            !backend_->SendAndReceive(IpcCommand::GetTargetInfo, nullptr, 0, bytes) ||
            bytes.size() != sizeof(GetTargetInfoResponse)) return false;
        GetTargetInfoResponse info{}; memcpy(&info, bytes.data(), sizeof(info));
        if (info.status != IpcStatus::Ok || info.pid != pid_ ||
            info.scope != (scope_ == "vm" ? IpcTargetScope::VirtualMachine : IpcTargetScope::Guest) ||
            (scope_ == "vm" ? info.addressBits != 0 : info.addressBits != 32 && info.addressBits != 64)) return false;
        addressBits_ = info.addressBits;
    }
    if (GetTickCount64() - started > 12000) { code = "expired"; return false; }
    backend_->StartHeartbeat();
    if (operation == "launch" && !request.at("launch").value("stopOnEntry", true) && !ResumeLaunchThread(0)) return false;
    disconnectedAt_ = GetTickCount64();
    code.clear();
    return true;
}
WorkOwner::~WorkOwner() { Stop(); }
void WorkOwner::Notify(std::function<void()> notify) { std::lock_guard<std::mutex> lock(mutex_); notify_ = std::move(notify); }
Json WorkOwner::Describe() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {{"success", true}, {"work_id", id_}, {"target_scope", scope_}, {"pid", pid_},
        {"address_bits", addressBits_}, {"outcome_unknown", outcomeUnknown_}};
}
bool WorkOwner::Matches(const std::string& backend, const std::string& scope, uint32_t pid) const {
    return backendName_ == backend && scope_ == scope && pid_ == pid;
}
bool WorkOwner::MatchesRequest(const std::string& backend, const std::string& id) const {
    return !requestId_.empty() && backendName_ == backend && requestId_ == id;
}
bool WorkOwner::Closing() const { std::lock_guard<std::mutex> lock(mutex_); return closing_; }
ULONGLONG WorkOwner::Expiry() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peer_ ? 0 : disconnectedAt_ + 60000;
}
bool WorkOwner::Reserve(const std::shared_ptr<Channel>& peer) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (peer_ || closing_ || inFlight_ || !requests_.empty() || GetTickCount64() >= disconnectedAt_ + 60000) return false;
    peer_ = peer; active_ = false; ++epoch_;
    return true;
}
bool WorkOwner::Activate(const std::shared_ptr<Channel>& peer) {
    { std::lock_guard<std::mutex> lock(mutex_); if (peer_ != peer || closing_) return false; active_ = true; }
    return FlushEvents();
}
void WorkOwner::Unbind(const std::shared_ptr<Channel>& peer) {
    std::function<void()> notify;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (peer_ != peer) return;
        peer_.reset(); active_ = false; disconnectedAt_ = GetTickCount64();
        if (inFlight_ || !requests_.empty()) outcomeUnknown_ = true;
        notify = notify_;
    }
    if (notify) notify();
}
bool WorkOwner::Send(const std::shared_ptr<Channel>& peer, uint32_t command, const void* data, uint32_t size) {
    std::lock_guard<std::mutex> lock(sendMutex_);
    IpcHeader header{command, size};
    if (peer->Write(&header, sizeof(header), 15000) && (!size || peer->Write(data, size, 15000))) return true;
    peer->Cancel(); Unbind(peer); return false;
}
void WorkOwner::OnEvent(uint32_t command, const uint8_t* data, uint32_t size) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closing_) return;
        // Ready is generated once for each authenticated work connection.
        if (command == static_cast<uint32_t>(IpcEvent::Ready)) return;
        if (events_.size() >= 256 || eventBytes_ + size > 4 * 1024 * 1024) {
            closing_ = true;
            if (peer_) peer_->Cancel();
            if (notify_) notify_();
            return;
        }
        Frame frame{command, {}};
        if (size) frame.payload.assign(data, data + size);
        eventBytes_ += size; events_.push_back(std::move(frame));
    }
    FlushEvents();
}
bool WorkOwner::FlushEvents() {
    // Serializes event draining; no callback can overtake older queued events.
    std::unique_lock<std::mutex> sendLock(sendMutex_);
    for (;;) {
        std::shared_ptr<Channel> peer; Frame frame{};
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!active_ || !peer_ || events_.empty() || closing_) return !closing_;
            peer = peer_; frame = std::move(events_.front()); events_.pop_front(); eventBytes_ -= frame.payload.size();
        }
        IpcHeader header{frame.command, static_cast<uint32_t>(frame.payload.size())};
        if (!peer->Write(&header, sizeof(header), 15000) ||
            (!frame.payload.empty() && !peer->Write(frame.payload.data(), frame.payload.size(), 15000))) {
            // Delivery became uncertain. Do not replay a possibly observed event.
            {
                std::lock_guard<std::mutex> lock(mutex_); outcomeUnknown_ = true;
            }
            peer->Cancel(); Unbind(peer); return false;
        }
    }
}
bool WorkOwner::Submit(const std::shared_ptr<Channel>& peer, uint32_t command, std::vector<uint8_t> payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (peer_ != peer || !active_ || closing_ || requests_.size() >= 16 ||
        requestBytes_ + payload.size() > 64 * 1024 * 1024) return false;
    requestBytes_ += payload.size();
    requests_.push_back({command, std::move(payload), epoch_}); cv_.notify_one(); return true;
}
bool WorkOwner::ResumeLaunchThread(uint32_t requestedThread) {
    if (!primaryThread_ || (requestedThread && requestedThread != mainThreadId_)) return true;
    if (ResumeThread(primaryThread_) == static_cast<DWORD>(-1)) return false;
    CloseHandle(primaryThread_); primaryThread_ = nullptr;
    return true;
}
std::vector<uint8_t> WorkOwner::Execute(const Request& request, bool& response) {
    const auto command = static_cast<IpcCommand>(request.command);
    response = true;
    if (command == IpcCommand::GetTargetInfo && scope_ == "host") {
        GetTargetInfoResponse info{targetProcess_ && WaitForSingleObject(targetProcess_, 0) == WAIT_TIMEOUT ?
            IpcStatus::Ok : IpcStatus::NotFound, IpcTargetScope::Host, pid_, addressBits_};
        return Bytes(info);
    }
    uint32_t resumedThread = 0;
    if (command == IpcCommand::Continue && request.payload.size() >= sizeof(ContinueRequest)) {
        ContinueRequest value{}; memcpy(&value, request.payload.data(), sizeof(value));
        if (primaryThread_ && (!value.threadId || value.threadId == mainThreadId_)) resumedThread = mainThreadId_;
        if (!ResumeLaunchThread(value.threadId)) return Bytes(IpcStatus::Error);
        if (!value.wantDetails) { response = false; backend_->SendCommand(command, request.payload.data(), static_cast<uint32_t>(request.payload.size())); return {}; }
    }
    if (command == IpcCommand::Heartbeat) {
        response = false; backend_->SendCommand(command); return {};
    }
    if (command == IpcCommand::Detach || command == IpcCommand::Shutdown) {
        if (!ResumeLaunchThread(0)) return Bytes(IpcStatus::Error);
        std::vector<uint8_t> detached;
        response = false;
        if (!backend_->SendAndReceive(command, request.payload.data(), static_cast<uint32_t>(request.payload.size()), detached, 3000) ||
            detached.size() < sizeof(IpcStatus)) {
            std::lock_guard<std::mutex> lock(mutex_); outcomeUnknown_ = true; if (peer_) peer_->Cancel(); return {};
        }
        IpcStatus status{}; memcpy(&status, detached.data(), sizeof(status));
        if (status != IpcStatus::Ok) {
            std::lock_guard<std::mutex> lock(mutex_); outcomeUnknown_ = true; if (peer_) peer_->Cancel(); return {};
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            releaseTarget_ = true; closing_ = true;
            if (peer_) peer_->Cancel();
            if (notify_) notify_();
        }
        return {};
    }
    std::vector<uint8_t> result;
    if (!backend_->SendAndReceive(command, request.payload.data(), static_cast<uint32_t>(request.payload.size()), result, 600000)) {
        std::lock_guard<std::mutex> lock(mutex_);
        outcomeUnknown_ = true; closing_ = true; if (peer_) peer_->Cancel();
        return {};
    }
    if (resumedThread && result.size() >= sizeof(ContinueResponse)) {
        ContinueResponse value{}; memcpy(&value, result.data(), sizeof(value));
        const uint64_t count = static_cast<uint64_t>(value.resumedCount) + value.stillStoppedCount;
        if (value.status == IpcStatus::Ok && count == (result.size() - sizeof(value)) / sizeof(uint32_t)) {
            bool found = false;
            for (uint32_t i = 0; i < value.resumedCount; ++i) {
                uint32_t id; memcpy(&id, result.data() + sizeof(value) + i * sizeof(id), sizeof(id));
                if (id == resumedThread) found = true;
            }
            if (!found) {
                const auto at = sizeof(value) + value.resumedCount * sizeof(uint32_t);
                const auto* bytes = reinterpret_cast<const uint8_t*>(&resumedThread);
                result.insert(result.begin() + at, bytes, bytes + sizeof(resumedThread));
                ++value.resumedCount; memcpy(result.data(), &value, sizeof(value));
            }
        }
    }
    if (command == IpcCommand::GetCapabilities && result.size() >= sizeof(GetCapabilitiesResponse) && scope_ == "host") {
        GetCapabilitiesResponse caps{}; memcpy(&caps, result.data(), sizeof(caps));
        if (caps.status == IpcStatus::Ok) {
            SetCommandSupported(caps.commands, IpcCommand::GetTargetInfo);
            memcpy(result.data(), &caps, sizeof(caps));
        }
    }
    return result;
}
void WorkOwner::Worker() {
    for (;;) {
        Request request{};
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return closing_ || !requests_.empty(); });
            if (closing_) break;
            request = std::move(requests_.front()); requests_.pop_front(); requestBytes_ -= request.payload.size();
            inFlight_ = true;
        }
        bool response = false;
        auto result = Execute(request, response);
        std::shared_ptr<Channel> peer;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            inFlight_ = false;
            if (request.epoch == epoch_ && active_) peer = peer_;
            else outcomeUnknown_ = true;
        }
        if (response && peer) { FlushEvents(); Send(peer, request.command, result.data(), static_cast<uint32_t>(result.size())); }
        if (notify_) notify_();
    }
}
void WorkOwner::Stop() {
    std::shared_ptr<Channel> peer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) return;
        stopped_ = true; closing_ = true; peer = peer_; peer_.reset(); cv_.notify_all();
    }
    if (peer) peer->Cancel();
    if (backend_) {
        // Ask an idle backend to release its stops/transactions before teardown.
        // Never wait behind an uncertain command holding the exchange mutex.
        bool idle;
        { std::lock_guard<std::mutex> lock(mutex_); idle = !inFlight_; }
        if (idle && backend_->IsConnected()) backend_->SendCommand(IpcCommand::Shutdown);
        // Cancels a pending exchange, then joins its sole reader and heartbeat.
        backend_->Disconnect();
    }
    if (worker_.joinable()) worker_.join();
    if (agentProcess_) {
        if (WaitForSingleObject(agentProcess_, 2000) == WAIT_TIMEOUT) {
            TerminateProcess(agentProcess_, 1); WaitForSingleObject(agentProcess_, 2000);
        }
        CloseHandle(agentProcess_); agentProcess_ = nullptr;
    }
    if (releaseTarget_ && job_) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        SetInformationJobObject(job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    }
    if (job_) { CloseHandle(job_); job_ = nullptr; }
    if (primaryThread_) { CloseHandle(primaryThread_); primaryThread_ = nullptr; }
    if (targetProcess_) { CloseHandle(targetProcess_); targetProcess_ = nullptr; }
}
} // namespace veh::remote
