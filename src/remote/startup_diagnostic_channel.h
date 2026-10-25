#pragma once
#include "common/startup_diagnostics.h"
#include <algorithm>
#include <string>
#include <memory>
#include <vector>

namespace veh::remote {
// Only the diagnostic writer is inherited. Never make runner sockets, token files,
// work handles or unrelated process handles inheritable for an agent.
class StartupDiagnosticChannel {
public:
    ~StartupDiagnosticChannel() { Close(); }
    StartupDiagnosticChannel() = default;
    StartupDiagnosticChannel(const StartupDiagnosticChannel&) = delete;
    StartupDiagnosticChannel& operator=(const StartupDiagnosticChannel&) = delete;
    void Close() { if (reader_) CloseHandle(reader_); reader_ = nullptr; }
    bool CreateAgent(const std::wstring& executable, wchar_t* command, PROCESS_INFORMATION& process) {
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        struct Resources {
            HANDLE writer = nullptr;
            LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
            std::vector<unsigned char> storage;
            ~Resources() {
                const DWORD error = GetLastError();
                if (attributes) DeleteProcThreadAttributeList(attributes);
                if (writer) CloseHandle(writer);
                SetLastError(error);
            }
        } resources;
        if (!CreatePipe(&reader_, &resources.writer, &security, sizeof(StartupDiagnostic))) return false;
        DWORD failure = 0;
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        resources.storage.resize(bytes);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(resources.storage.data());
        bool created = false;
        do {
            if (!SetHandleInformation(reader_, HANDLE_FLAG_INHERIT, 0)) { failure = GetLastError(); break; }
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) { failure = GetLastError(); break; }
            resources.attributes = attributes;
            if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    &resources.writer, sizeof(resources.writer), nullptr, nullptr)) { failure = GetLastError(); break; }
            // Build a private child environment; do not mutate the resident's environment.
            auto releaseEnvironment = [](wchar_t* block) { FreeEnvironmentStringsW(block); };
            std::unique_ptr<wchar_t, decltype(releaseEnvironment)> inherited(GetEnvironmentStringsW(), releaseEnvironment);
            if (!inherited) { failure = GetLastError(); break; }
            std::vector<std::wstring> entries;
            for (const wchar_t* entry = inherited.get(); *entry; entry += wcslen(entry) + 1) {
                const std::wstring value(entry);
                const auto equals = value.find(L'=');
                if (equals != std::wstring::npos &&
                    _wcsicmp(value.substr(0, equals).c_str(), kStartupDiagnosticHandle) == 0) continue;
                entries.push_back(value);
            }
            entries.push_back(std::wstring(kStartupDiagnosticHandle) + L"=" +
                std::to_wstring(reinterpret_cast<uintptr_t>(resources.writer)));
            std::sort(entries.begin(), entries.end(),
                [](const auto& a, const auto& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
            std::vector<wchar_t> environment;
            for (const auto& entry : entries) {
                environment.insert(environment.end(), entry.begin(), entry.end());
                environment.push_back(0);
            }
            environment.push_back(0);
            STARTUPINFOEXW startup{};
            startup.StartupInfo.cb = sizeof(startup);
            startup.lpAttributeList = attributes;
            created = CreateProcessW(executable.c_str(), command, nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                environment.data(), nullptr, &startup.StartupInfo, &process) != FALSE;
            if (!created) failure = GetLastError();
        } while (false);
        if (!created) { Close(); SetLastError(failure); }
        return created;
    }
    bool Read(StartupDiagnostic& record) const {
        DWORD available = 0, received = 0;
        // No wait for EOF, and no blocking read of an untrusted length.
        return reader_ && PeekNamedPipe(reader_, nullptr, 0, nullptr, &available, nullptr) &&
            available == sizeof(record) && ReadFile(reader_, &record, sizeof(record), &received, nullptr) &&
            received == sizeof(record) && ValidStartupDiagnostic(record);
    }
private:
    HANDLE reader_ = nullptr;
};
} // namespace veh::remote
