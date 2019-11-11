/*
Copyright 2018 Shirao Shotaro
Released under the MIT license
https://opensource.org/licenses/mit-license.php
*/
#pragma once
#ifndef TCP11_TCP_HPP
#define TCP11_TCP_HPP
#if defined(_WINDOWS) || defined(__GNUC__)
#if defined(_WINDOWS)
#include <WinSock2.h>
#elif defined(__GNUC__)
//#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#define SOCKET int
#define INVALID_SOCKET 0
#endif
#include <streambuf>
#include <sstream>
#include <ostream>
#include <memory>
namespace tcp11 {
namespace _internal {
class tcp_logs {
public:
	void setTrLogDest(const std::ostream & redirect_streambuf);
	void setLogDest(const std::ostream & redirect_streambuf);
	void setTrLogEnable(const bool enable = true);
	void setLogEnable(const bool enable = true);
protected:
	explicit tcp_logs() noexcept;
	tcp_logs(const tcp_logs &) = delete;
	tcp_logs(tcp_logs &&) = delete;
	std::ostream & clog(void);
	std::ostream & cerr(void);
private:
	std::ostream clog_, cerr_;
	bool clogen_, cerren_;
	std::stringstream nulldump_;
};

class tcp_streambuf : public ::std::streambuf, public tcp_logs {
public:
	enum : size_t { kBufferSize = 4096 };
	explicit tcp_streambuf(const std::string & ipaddress, const int port) noexcept;
	virtual ~tcp_streambuf();
	bool connect(void);
	bool bind(const SOCKET & socket);
	bool disconnect(void);
	bool send(void);
	bool receive(void);
	virtual bool isValid(void) const;
	const std::string & getIpAddress(void) const;
	int getPort(void) const;
private:
	virtual int sync(void) override;
	virtual int_type underflow(void) override;
	char rbuffer_[kBufferSize];
	char wbuffer_[kBufferSize];
	const std::string ipaddress_;
	const int port_;
	addrinfo addr_;
	SOCKET socket_;
};

class tcp_iostream : public std::iostream {
public:
	const tcp_streambuf & tcpbuf(void) const;
protected:
	explicit tcp_iostream(std::unique_ptr<tcp_streambuf> && tcp_streambuf_initialized_uptr) noexcept;
	virtual ~tcp_iostream(void);
	tcp_streambuf & tcpbuf(void);
	std::unique_ptr<tcp_streambuf> tcp_streambuf_uptr_;
};
} // end of _internal

///
/// @brief tcp stream container.
///
class tcp : public _internal::tcp_iostream {
public:
	
	tcp() = delete;	///< Default constructor is deleted.
	tcp(const tcp &) = delete; ///< Copy constructor is deleted.

	///
	/// @brief Constructor as client.
	///
	/// This is only for configuration. Call connect() function to connect to a host.
	/// When you use as host, make instance by tcp_host class.
	///
	/// @param address distination address
	/// @param port port number
	///
	explicit tcp(const std::string & address, const int port) noexcept;

	///
	/// @brief Move Constructor.
	///
	/// @param m another tcp instance.
	///
	tcp(tcp && m) noexcept;

	///
	/// @brief Destructor
	///
	virtual ~tcp();

	///
	/// @brief Connect to a server.
	///
	/// This function is available for a client instance.
	/// When this is a host instance, this function does nothing.
	/// If you call this function twice or more, this function does nothing.
	///
	/// @retval true connected successfully.
	/// @retval false connection failed.
	///
	bool connect(void);

	///
	/// @brief Disconnect from server.
	///
	/// This function is available for a client or server instance.
	/// You cannot reuse this instance.
	///
	bool disconnect(void);

	///
	/// @brief Get if this instance is valid.
	///
	/// @retval true valid.
	/// @retval false invalid.
	///
	bool isValid(void) const;

	///
	/// @brief Get if this instance is valid.
	///
	/// This function calls isValid() internally.
	///
	/// @sa isValid()
	/// @retval true valid.
	/// @retval false invalid.
	///
	bool operator()(void) const;

	///
	/// @brief Set trace log destination
	///
	/// Default is to std::cout
	///
	/// @param redirect_streambuf logs destination.
	///
	void setTrLogDest(const std::ostream & redirect_streambuf);

	///
	/// @brief Set important logs destination
	///
	/// Default is to std::cerr
	///
	/// @param redirect_streambuf log destination.
	///
	void setLogDest(const std::ostream & redirect_streambuf);

	void setTrLogEnable(const bool enable = true);
	void setLogEnable(const bool enable = true);

	///
	/// @brief information of client as string
	///
	/// @return client information string
	///
	std::string to_string(void) const;

	friend std::ostream & operator<<(std::ostream & os, const tcp & tcp) noexcept;

	///
	/// @brief Validator of Ip Address string
	///
	/// this validator currently checks if ipaddress is not empty.
	///
	/// @param ipaddress ipaddress string
	///
	/// @retval true valid.
	/// @retval false invalid.
	///
	static bool isValidIpAddress(const std::string & ipaddress);

	///
	/// @brief Validator of Port Number
	///
	/// this validator checks if (1 <= port && port <= 65535)
	///
	/// @param port port number.
	///
	/// @retval true valid.
	/// @retval false invalid.
	///
	static bool isValidPortNumber(const int port);

private:
	friend class tcp_host;
};

class tcp_host : public _internal::tcp_logs{
public:

	///
	/// @brief Constructor
	///
	/// This function is only for configuration.
	/// Call prepare(), listen(), accept() function to accept new clients. 
	///
	/// @param port using connection port.
	///
	tcp_host(const int port) noexcept;
	
	///
	/// @brief Prepare for connection.
	///
	/// @retval true Finished preparing successfully.
	/// @retval false Failed.
	///
	bool prepare(void);

	///
	/// @brief Listen for a new client.
	///
	/// THIS IS BLOCKING FUNCTION.
	/// Wait for a new client.
	///
	/// @retval true a new client is waiting accepted. Call accept() function.
	/// @retval false error has occured.
	///
	bool listen(void);

	///
	/// @brief Accept a new client.
	///
	/// Recommend to call tcp::isValid() function and check the tcp instance is valid.
	///
	/// @return new tcp instance.
	///
	tcp accept(void);
	
	///
	/// @brief close host.
	///
	/// @retval true Currently Always Success.
	///
	bool close(void);

	///
	/// @brief get port no.
	///
	/// @return port number
	///
	int getPort(void) const;

private:
	const int port_;
	struct addrinfo addr_;
	SOCKET listen_socket_;

};

}

#endif
#endif