#if defined(_WINDOWS) || defined(__GNUC__)
#include "tcp.hpp"
#include <cstring>
#include <iostream>
#include <cassert>

#if defined(_WINDOWS)
#include <ws2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#elif defined(__GNUC__)
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

//##########################################################################################################
//# tcp_logs
//##########################################################################################################
tcp11::_internal::tcp_logs::tcp_logs() noexcept : clog_(std::cout.rdbuf()), cerr_(std::cerr.rdbuf()), clogen_(false), cerren_(true) {}
std::ostream & tcp11::_internal::tcp_logs::clog(void) { this->nulldump_.str(""); return (this->clogen_ ? this->clog_ : this->nulldump_); }
std::ostream & tcp11::_internal::tcp_logs::cerr(void) { this->nulldump_.str(""); return (this->cerren_ ? this->cerr_ : this->nulldump_); }
void tcp11::_internal::tcp_logs::setTrLogDest(const std::ostream & redirect_streambuf) { this->clog_.rdbuf(redirect_streambuf.rdbuf()); }
void tcp11::_internal::tcp_logs::setLogDest(const std::ostream & redirect_streambuf) { this->cerr_.rdbuf(redirect_streambuf.rdbuf()); }
void tcp11::_internal::tcp_logs::setTrLogEnable(const bool enable) { this->clogen_ = enable; }
void tcp11::_internal::tcp_logs::setLogEnable(const bool enable) { this->cerren_ = enable; }

//##########################################################################################################
//# tcp_streambuf Common
//##########################################################################################################
#ifdef _DEBUG
#include <iomanip>
namespace temporary { std::string toHexString(const char * src, const int size) {
	std::stringstream sstr;
	for (int i = 0; i < size; i++) sstr << " " << std::setfill('0') << std::setw(2) << std::hex << (int)(src[i]);
	return (sstr.str().empty() ? "" : sstr.str().substr(1));
}}
#endif

tcp11::_internal::tcp_streambuf::tcp_streambuf(const std::string & ipaddress, const int port) noexcept
	: ipaddress_(ipaddress), port_(port), socket_(INVALID_SOCKET) {
	assert(tcp::isValidIpAddress(ipaddress_));
	assert(tcp::isValidPortNumber(port_));
	// For Buffer
	this->setp(this->wbuffer_, this->wbuffer_ + this->kBufferSize);
	this->setg(this->rbuffer_, this->rbuffer_ + this->kBufferSize, this->rbuffer_ + this->kBufferSize);
	// For Network
	std::memset(&this->addr_, 0, sizeof(this->addr_));
	this->addr_.ai_family = AF_UNSPEC;
	this->addr_.ai_socktype = SOCK_STREAM;
	//this->addr_.ai_protocol = IPPROTO_TCP;
	this->clog() << "Created tcp instance. Destination = " << ipaddress << " : " << port << std::endl;
}
bool tcp11::_internal::tcp_streambuf::send(void){
	if (pptr() == gptr()) return 0;
	const auto will_send_size = static_cast<int>(pptr() - pbase());
	const auto send_size = ::send(this->socket_, this->wbuffer_, static_cast<int>(will_send_size), 0);
#ifdef _DEBUG
	this->clog() << "tcp send (BYTE) = " << temporary::toHexString(this->wbuffer_, will_send_size) << std::endl;
#endif
	this->clog() << "tcp send = " << std::string(this->wbuffer_, will_send_size) << std::endl;
	pbump(static_cast<int>(pbase() - pptr()));
	return (will_send_size == send_size);
}
bool tcp11::_internal::tcp_streambuf::receive(void){
	const auto size = recv(this->socket_, this->rbuffer_, this->kBufferSize, 0);
	this->setg(this->rbuffer_, this->rbuffer_, this->rbuffer_ + size);
#ifdef _DEBUG
	this->clog() << "tcp recv (BYTE) = " << temporary::toHexString(this->rbuffer_, size) << std::endl;
#endif
	this->clog() << "tcp recv = " << std::string(this->rbuffer_, size) << std::endl;
	return true;
}
bool tcp11::_internal::tcp_streambuf::bind(const SOCKET & socket){
	if (this->socket_ != INVALID_SOCKET) return false;
	this->socket_ = socket;
	return true;
}
tcp11::_internal::tcp_streambuf::~tcp_streambuf() {}
int tcp11::_internal::tcp_streambuf::sync(void){ return (this->send() ? 0 : -1); }
std::streambuf::int_type tcp11::_internal::tcp_streambuf::underflow(void){
	if (this->receive()) return traits_type::to_int_type(*this->gptr());
	return traits_type::eof();
}
const std::string & tcp11::_internal::tcp_streambuf::getIpAddress(void) const { return this->ipaddress_; }
int tcp11::_internal::tcp_streambuf::getPort(void) const { return this->port_; }
bool tcp11::_internal::tcp_streambuf::isValid(void) const { return (this->socket_ != INVALID_SOCKET); }

#if defined(_WINDOWS)
//##########################################################################################################
//# tcp_streambuf for WINDOWS
//##########################################################################################################
namespace {
struct tcp_wsadata {
private:
	bool available;
public:
	WSADATA wsaData;
	tcp_wsadata(void) { available = (WSAStartup(MAKEWORD(2, 2), &this->wsaData) == 0); }
	~tcp_wsadata(void) { if (available) WSACleanup(); }
	operator bool() { return available; }
};
std::unique_ptr<tcp_wsadata> wsadata_ptr_;
bool startupWSA(void) { if (!wsadata_ptr_) wsadata_ptr_ = std::make_unique<tcp_wsadata>(); return *wsadata_ptr_; }
}
bool tcp11::_internal::tcp_streambuf::connect(void){
	if (!startupWSA()) { cerr() << "WSAStartup failed." << std::endl; return false; }
	if (this->socket_ != INVALID_SOCKET) return false;
	addrinfo * addr_res = nullptr; int res = 0;
	if ((res = getaddrinfo(this->getIpAddress().c_str(), std::to_string(this->getPort()).c_str(), &this->addr_, &addr_res)) != 0){
		std::cerr << "getaddrinfo failed with error" + std::to_string(res) << std::endl; return false;
	}
	for (addrinfo * ptr = addr_res; ptr != nullptr; ptr = ptr->ai_next) {
		this->socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (this->socket_ == INVALID_SOCKET) {
			this->cerr() << "socket failed with error" + std::to_string(WSAGetLastError()) << std::endl; return false;
		}
		if (::connect(this->socket_, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
			closesocket(this->socket_); this->socket_ = INVALID_SOCKET; continue;
		}
		break;
	}
	freeaddrinfo(addr_res);
	if (this->socket_ == INVALID_SOCKET) {
		this->cerr() << "Unable to connect to server!" << std::endl; return false;
	}
	this->clog() << "Connected to the server. Socket ID = " << this->socket_ << std::endl;
	return true;
}
bool tcp11::_internal::tcp_streambuf::disconnect(void){
	if (shutdown(this->socket_, SD_SEND) == SOCKET_ERROR) {
		this->cerr() << "shutdown failed with error" + std::to_string(WSAGetLastError()) << std::endl;
		closesocket(this->socket_); this->socket_ = INVALID_SOCKET; return true;
	}
	return false;
}

#elif defined(__GNUC__)
//##########################################################################################################
//# tcp_streambuf for GNUC
//##########################################################################################################
bool tcp11::_internal::tcp_streambuf::connect(void){
	this->clog() << "Start to connect." << std::endl;
	if (this->socket_ != INVALID_SOCKET) return false;
	addrinfo * addr_res = nullptr; int res = 0;
	if ((res = getaddrinfo(this->getIpAddress().c_str(), std::to_string(this->getPort()).c_str(), &this->addr_, &addr_res)) != 0){
		std::cerr << "getaddrinfo failed with error" + std::to_string(res) << std::endl; return false;
	}
	this->clog() << "Got addrinfo." << std::endl;

	for (addrinfo * ptr = addr_res; ptr != nullptr; ptr = ptr->ai_next) {
		this->socket_ = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		this->clog() << "Socketed = " << this->socket_ << std::endl;
		if (this->socket_ == INVALID_SOCKET) {
			this->cerr() << "socket failed." << std::endl; return false;
		}
		if (::connect(this->socket_, ptr->ai_addr, ptr->ai_addrlen) == -1) {
			::close(this->socket_); this->socket_ = INVALID_SOCKET; continue;
		}
		this->clog() << "Connected" << std::endl;
		break;
	}
	freeaddrinfo(addr_res);
	if (this->socket_ == INVALID_SOCKET) {
		this->cerr() << "Unable to connect to server!" << std::endl; return false;
	}
	this->clog() << "Connected to the server. Socket ID = " << this->socket_ << std::endl;
	return true;
}
bool tcp11::_internal::tcp_streambuf::disconnect(void){
	if(this->socket_ != INVALID_SOCKET){
		if(::close(this->socket_) == 0){
			this->socket_ = INVALID_SOCKET; return true;
		}
	}
	return false;
}
#endif

//##########################################################################################################
//# tcp_iostream
//##########################################################################################################
tcp11::_internal::tcp_iostream::tcp_iostream(std::unique_ptr<tcp_streambuf>&& tcp_streambuf_initialized_uptr) noexcept
	: std::iostream(tcp_streambuf_initialized_uptr.get()) {
	this->tcp_streambuf_uptr_ = std::move(tcp_streambuf_initialized_uptr);
}
tcp11::_internal::tcp_iostream::~tcp_iostream(void) { /* no operation */ }
tcp11::_internal::tcp_streambuf & tcp11::_internal::tcp_iostream::tcpbuf(void)
{ return *(this->tcp_streambuf_uptr_.get()); }
const tcp11::_internal::tcp_streambuf & tcp11::_internal::tcp_iostream::tcpbuf(void) const
{ return *(this->tcp_streambuf_uptr_.get()); }

//##########################################################################################################
//# tcp
//##########################################################################################################
tcp11::tcp::tcp(const std::string & address, const int port) noexcept
	: tcp_iostream(std::make_unique<_internal::tcp_streambuf>(address, port)) {}
tcp11::tcp::tcp(tcp && m) noexcept : tcp_iostream(std::move(m.tcp_streambuf_uptr_)) {}
tcp11::tcp::~tcp(){}
bool tcp11::tcp::connect(void){ return this->tcpbuf().connect(); }
bool tcp11::tcp::disconnect(void){ return this->tcpbuf().disconnect(); }
bool tcp11::tcp::isValid(void) const { return this->tcpbuf().isValid(); }
bool tcp11::tcp::operator()(void) const { return this->isValid(); }
void tcp11::tcp::setTrLogDest(const std::ostream & redirect_streambuf)
{ this->tcpbuf().setTrLogDest(redirect_streambuf); }
void tcp11::tcp::setLogDest(const std::ostream & redirect_streambuf)
{ this->tcpbuf().setLogDest(redirect_streambuf); }
void tcp11::tcp::setTrLogEnable(const bool enable) { this->tcpbuf().setTrLogEnable(enable); }
void tcp11::tcp::setLogEnable(const bool enable) { this->tcpbuf().setLogEnable(enable); }
std::string tcp11::tcp::to_string(void) const
{ return std::string("tcp : ipaddress = " + this->tcpbuf().getIpAddress() + " port = " + std::to_string(this->tcpbuf().getPort())); }
bool tcp11::tcp::isValidIpAddress(const std::string & ipaddress) { return !ipaddress.empty(); }
bool tcp11::tcp::isValidPortNumber(const int port) { return (port > 0 && port < 65536); }

//##########################################################################################################
//# tcp_host Common
//##########################################################################################################
tcp11::tcp_host::tcp_host(const int port) noexcept : port_(port) {
	assert(tcp::isValidPortNumber(port));
	std::memset(&this->addr_, 0, sizeof(this->addr_));
	this->addr_.ai_family = AF_INET;
	this->addr_.ai_socktype = SOCK_STREAM;
	this->addr_.ai_protocol = IPPROTO_TCP;
	this->addr_.ai_flags = AI_PASSIVE;
}
int tcp11::tcp_host::getPort(void) const { return this->port_; }

#if defined(_WINDOWS)
//##########################################################################################################
//# tcp_host for WINDOWS
//##########################################################################################################
bool tcp11::tcp_host::prepare(void){
	if (!startupWSA()) { cerr() << "WSAStartup failed." << std::endl; return false; }
	addrinfo * addr_res = nullptr; int res = 0;
	if ((res = getaddrinfo(nullptr, std::to_string(this->port_).c_str(), &this->addr_, &addr_res)) != 0) {
		cerr() << "getaddrinfo failed with error " << res << std::endl; return false;
	}
	this->listen_socket_ = socket(addr_res->ai_family, addr_res->ai_socktype, addr_res->ai_protocol);
	if (this->listen_socket_ == INVALID_SOCKET) {
		cerr() << "socket failed with error " + std::to_string(WSAGetLastError()) << std::endl;
		freeaddrinfo(addr_res); return false;
	}
	if ((res = ::bind(this->listen_socket_, addr_res->ai_addr, (int)addr_res->ai_addrlen)) == SOCKET_ERROR) {
		cerr() << "bind failed with error " + std::to_string(WSAGetLastError()) << std::endl;
		freeaddrinfo(addr_res);	closesocket(this->listen_socket_); return false;
	}
	freeaddrinfo(addr_res);
	return true;
}
bool tcp11::tcp_host::listen(void){
	clog() << "Waiting new client." << std::endl;
	if (::listen(this->listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
		cerr() << "listen failed with error " + std::to_string(WSAGetLastError()) << std::endl;
		closesocket(this->listen_socket_); return false;
	}
	return true;
}
tcp11::tcp tcp11::tcp_host::accept(void){
	struct sockaddr_in client_info; int client_info_sizeof = sizeof(client_info);
	int client_port = this->port_; std::string client_ipaddress = "";
	SOCKET client_socket = ::accept(this->listen_socket_, (struct sockaddr *)&client_info, &client_info_sizeof);
	if (client_socket != INVALID_SOCKET) {
		char buf[32];
		InetNtop(AF_INET, &client_info.sin_addr, buf, sizeof(buf));
		client_ipaddress = std::string(buf);
		client_port = ntohs(client_info.sin_port);
		clog() << "Accepted a client from " << client_ipaddress << " : " << client_port << std::endl;
	}
	else cerr() << "Failed to accept a client with error code " + std::to_string(WSAGetLastError()) << std::endl;
	tcp client = tcp(client_ipaddress, client_port);
	client.tcpbuf().bind(client_socket);
	return std::move(client);
}
bool tcp11::tcp_host::close(void){
	if (closesocket(this->listen_socket_) != 0) {
		cerr() << "Failed to shutdown host with error code " + std::to_string(WSAGetLastError()) << std::endl;
		return false;
	}
	return true;
}

#elif defined(__GNUC__)
//##########################################################################################################
//# tcp_host for GNUC
//##########################################################################################################
bool tcp11::tcp_host::prepare(void){
	addrinfo * addr_res = nullptr; int res = 0;
	if ((res = getaddrinfo(nullptr, std::to_string(this->port_).c_str(), &this->addr_, &addr_res)) != 0) {
		cerr() << "getaddrinfo failed with error " << res << std::endl; return false;
	}
	this->listen_socket_ = socket(addr_res->ai_family, addr_res->ai_socktype, addr_res->ai_protocol);
	if (this->listen_socket_ == INVALID_SOCKET) {
		cerr() << "socket failed." << std::endl;
		freeaddrinfo(addr_res); return false;
	}
	if ((res = ::bind(this->listen_socket_, addr_res->ai_addr, (int)addr_res->ai_addrlen)) == -1) {
		cerr() << "bind failed with error" << std::endl;
		freeaddrinfo(addr_res);	::close(this->listen_socket_); return false;
	}
	freeaddrinfo(addr_res);
	return true;
}
bool tcp11::tcp_host::listen(void){
	clog() << "Waiting new client." << std::endl;
	if (::listen(this->listen_socket_, SOMAXCONN) != 0) {
		cerr() << "listen failed." << std::endl;
		::close(this->listen_socket_); return false;
	}
	return true;
}
tcp11::tcp tcp11::tcp_host::accept(void){
	struct sockaddr_in client_info; int client_info_sizeof = sizeof(client_info);
	int client_port = this->port_; std::string client_ipaddress = "";
	SOCKET client_socket = ::accept(this->listen_socket_, (struct sockaddr *)&client_info, (socklen_t*)&client_info_sizeof);
	if (client_socket != INVALID_SOCKET) {
		char buf[32];
		inet_ntop(AF_INET, &client_info.sin_addr, buf, sizeof(buf));
		client_ipaddress = std::string(buf);
		client_port = ntohs(client_info.sin_port);
		clog() << "Accepted a client from " << client_ipaddress << " : " << client_port << std::endl;
	}
	else cerr() << "Failed to accept a client." << std::endl;
	tcp client = tcp(client_ipaddress, client_port);
	client.tcpbuf().bind(client_socket);
	return std::move(client);
}
bool tcp11::tcp_host::close(void){
	if (::close(this->listen_socket_) != 0) {
		cerr() << "Failed to shutdown host." << std::endl;
		return false;
	}
	return true;
}
#endif
std::ostream & operator<<(std::ostream & os, const tcp11::tcp & tcp) noexcept { os << tcp.to_string(); return os; }
#endif