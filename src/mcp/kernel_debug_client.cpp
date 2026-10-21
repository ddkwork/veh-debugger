#include "kernel_debug_client.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <chrono>
#include <cstdio>
#include <thread>

namespace veh {
namespace {

uint64_t NowMs()
{
	return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count());
}

class PipeTransport : public KdTransport {
public:
	explicit PipeTransport(HANDLE h) : h_(h) {}
	~PipeTransport() override { CloseHandle(h_); }
	bool Write(const void* data, size_t size) override
	{
		DWORD n = 0;
		return WriteFile(h_, data, static_cast<DWORD>(size), &n, nullptr) && n == size;
	}
	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		const uint64_t end = NowMs() + timeout_ms;
		for (;;) {
			DWORD avail = 0;
			if (!PeekNamedPipe(h_, nullptr, 0, nullptr, &avail, nullptr))
				return -1;
			if (avail) {
				DWORD n = 0;
				if (!ReadFile(h_, buffer, static_cast<DWORD>(avail < max ? avail : max), &n, nullptr))
					return -1;
				return static_cast<int>(n);
			}
			if (NowMs() >= end)
				return 0;
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}

private:
	HANDLE h_;
};

class ComTransport : public KdTransport {
public:
	explicit ComTransport(HANDLE h) : h_(h) {}
	~ComTransport() override { CloseHandle(h_); }
	bool Write(const void* data, size_t size) override
	{
		DWORD n = 0;
		return WriteFile(h_, data, static_cast<DWORD>(size), &n, nullptr) && n == size;
	}
	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		COMMTIMEOUTS t = {};
		t.ReadIntervalTimeout = MAXDWORD;
		t.ReadTotalTimeoutMultiplier = MAXDWORD;
		t.ReadTotalTimeoutConstant = timeout_ms ? timeout_ms : 1;
		SetCommTimeouts(h_, &t);
		DWORD n = 0;
		if (!ReadFile(h_, buffer, static_cast<DWORD>(max), &n, nullptr))
			return -1;
		return static_cast<int>(n);
	}

private:
	HANDLE h_;
};

class TcpTransport : public KdTransport {
public:
	explicit TcpTransport(SOCKET s) : s_(s) {}
	~TcpTransport() override { closesocket(s_); }
	bool Write(const void* data, size_t size) override
	{
		return send(s_, static_cast<const char*>(data), static_cast<int>(size), 0) == static_cast<int>(size);
	}
	int Read(uint8_t* buffer, size_t max, uint32_t timeout_ms) override
	{
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s_, &set);
		timeval tv = { static_cast<long>(timeout_ms / 1000), static_cast<long>((timeout_ms % 1000) * 1000) };
		const int ready = select(0, &set, nullptr, nullptr, &tv);
		if (ready <= 0)
			return ready;
		const int n = recv(s_, reinterpret_cast<char*>(buffer), static_cast<int>(max), 0);
		return n > 0 ? n : -1;
	}

private:
	SOCKET s_;
};

const char kHex[] = "0123456789abcdef";

} // namespace

std::unique_ptr<KdTransport> OpenKdTransport(const std::string& kind, const std::string& address, uint32_t baud,
	std::string* error)
{
	if (kind == "pipe" || kind == "com") {
		std::string path = address;
		if (kind == "com" && path.rfind("\\\\.\\", 0) != 0)
			path = "\\\\.\\" + path; // COM10 and up need the device prefix
		HANDLE h = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			*error = "open " + path + " failed: " + std::to_string(GetLastError()) +
				(GetLastError() == ERROR_PIPE_BUSY ? " (another client is connected)" : "");
			return nullptr;
		}
		if (kind == "pipe")
			return std::make_unique<PipeTransport>(h);
		DCB dcb = { sizeof(dcb) };
		GetCommState(h, &dcb);
		dcb.BaudRate = baud ? baud : 115200;
		dcb.ByteSize = 8;
		dcb.Parity = NOPARITY;
		dcb.StopBits = ONESTOPBIT;
		dcb.fBinary = TRUE;
		if (!SetCommState(h, &dcb)) {
			*error = "configure " + path + " failed: " + std::to_string(GetLastError());
			CloseHandle(h);
			return nullptr;
		}
		return std::make_unique<ComTransport>(h);
	}
	if (kind == "tcp") {
		WSADATA wsa;
		WSAStartup(MAKEWORD(2, 2), &wsa);
		const size_t colon = address.rfind(':');
		if (colon == std::string::npos) {
			*error = "tcp address must be host:port";
			return nullptr;
		}
		addrinfo hints = {};
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		addrinfo* found = nullptr;
		if (getaddrinfo(address.substr(0, colon).c_str(), address.substr(colon + 1).c_str(), &hints, &found) != 0 || !found) {
			*error = "resolve " + address + " failed";
			return nullptr;
		}
		SOCKET s = socket(found->ai_family, found->ai_socktype, found->ai_protocol);
		const bool ok = s != INVALID_SOCKET && connect(s, found->ai_addr, static_cast<int>(found->ai_addrlen)) == 0;
		freeaddrinfo(found);
		if (!ok) {
			*error = "connect " + address + " failed: " + std::to_string(WSAGetLastError());
			if (s != INVALID_SOCKET)
				closesocket(s);
			return nullptr;
		}
		const BOOL nodelay = TRUE;
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
		return std::make_unique<TcpTransport>(s);
	}
	*error = "transport must be pipe, com or tcp";
	return nullptr;
}

bool KernelDebugClient::Send(const std::string& payload)
{
	uint8_t sum = 0;
	for (char c : payload)
		sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(c));
	const std::string frame = "$" + payload + "#" + kHex[sum >> 4] + kHex[sum & 15];
	return transport_->Write(frame.data(), frame.size());
}

bool KernelDebugClient::Receive(std::string* payload, uint32_t timeout_ms)
{
	const uint64_t end = NowMs() + timeout_ms;
	for (;;) {
		const size_t start = buffer_.find('$');
		if (start != std::string::npos) {
			const size_t hash = buffer_.find('#', start);
			if (hash != std::string::npos && buffer_.size() >= hash + 3) {
				*payload = buffer_.substr(start + 1, hash - start - 1);
				buffer_.erase(0, hash + 3);
				if (ack_)
					transport_->Write("+", 1);
				return true;
			}
		}
		const uint64_t now = NowMs();
		if (now >= end)
			return false;
		uint8_t chunk[4096];
		const int n = transport_->Read(chunk, sizeof(chunk), static_cast<uint32_t>(end - now < 50 ? end - now : 50));
		if (n < 0)
			return false;
		buffer_.append(reinterpret_cast<char*>(chunk), static_cast<size_t>(n));
	}
}

bool KernelDebugClient::Request(const std::string& packet, std::string* reply, uint32_t timeout_ms)
{
	return Send(packet) && Receive(reply, timeout_ms);
}

bool KernelDebugClient::Handshake(std::string* stop, std::string* error)
{
	std::string reply;
	// The first packet halts a target that was running; give it time.
	if (!Request("qSupported:swbreak+;hwbreak+;xmlRegisters=i386", &reply, 15000)) {
		*error = "no answer to qSupported (is the stub enabled and the transport right?)";
		return false;
	}
	if (Request("QStartNoAckMode", &reply) && reply == "OK")
		ack_ = false;
	if (!Request("?", stop)) {
		*error = "no stop reason";
		return false;
	}
	last_stop_ = *stop;
	running_ = false;
	return true;
}

bool KernelDebugClient::Resume(const std::string& packet)
{
	if (!Send(packet))
		return false;
	running_ = true;
	return true;
}

bool KernelDebugClient::WaitStop(std::string* stop, uint32_t timeout_ms)
{
	if (!running_) {
		*stop = last_stop_;
		return true;
	}
	if (!Receive(stop, timeout_ms))
		return false;
	running_ = false;
	last_stop_ = *stop;
	return true;
}

bool KernelDebugClient::Interrupt(std::string* stop, uint32_t timeout_ms)
{
	if (!running_) {
		*stop = last_stop_;
		return true;
	}
	if (!transport_->Write("\x03", 1))
		return false;
	return WaitStop(stop, timeout_ms);
}

} // namespace veh
