#pragma once

#include <atomic>
#include <memory>
#include <vector>
#include <deque>
#include <array>

#include "Common.h"
namespace ba = boost::asio;
namespace bi = ba::ip;


namespace czr
{
namespace p2p
{


using Mutex = std::mutex;
using RecursiveMutex = std::recursive_mutex;
using SharedMutex = boost::shared_mutex;

using Guard = std::lock_guard<std::mutex>;
using UniqueGuard = std::unique_lock<std::mutex>;
using RecursiveGuard = std::lock_guard<std::recursive_mutex>;
using ReadGuard = boost::shared_lock<boost::shared_mutex>;
using UpgradableGuard = boost::upgrade_lock<boost::shared_mutex>;
using UpgradeGuard = boost::upgrade_to_unique_lock<boost::shared_mutex>;
using WriteGuard = boost::unique_lock<boost::shared_mutex>;

class UDPDatagram
{
public:
	UDPDatagram(bi::udp::endpoint const& _ep): locus(_ep) {}
	UDPDatagram(bi::udp::endpoint const& _ep, bytes _data): data(_data), locus(_ep) {}
	bi::udp::endpoint const& endpoint() const { return locus; }

	bytes data;
protected:
	bi::udp::endpoint locus;
};


struct RLPXDatagramFace: public UDPDatagram
{
	static uint32_t futureFromEpoch(std::chrono::seconds _sec) { return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + _sec).time_since_epoch()).count()); }
	static uint32_t secondsSinceEpoch() { return static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now()).time_since_epoch()).count()); }
	static Public authenticate(bytesConstRef _sig, bytesConstRef _rlp);

	RLPXDatagramFace(bi::udp::endpoint const& _ep): UDPDatagram(_ep) {}
	virtual ~RLPXDatagramFace() = default;

	virtual h256 sign(Secret const& _from);
	virtual uint8_t packetType() const = 0;

	virtual void streamRLP(RLPStream&) const = 0;
	virtual void interpretRLP(bytesConstRef _bytes) = 0;
};


struct UDPSocketFace
{
	virtual bool send(UDPDatagram const& _msg) = 0;
	virtual void disconnect() = 0;
};


struct UDPSocketEvents
{
	virtual ~UDPSocketEvents() = default;
	virtual void onDisconnected(UDPSocketFace*) {}
	virtual void onReceived(UDPSocketFace*, bi::udp::endpoint const& _from, bytesConstRef _packetData) = 0;
};


template <typename Handler, unsigned MaxDatagramSize>
class UDPSocket: UDPSocketFace, public std::enable_shared_from_this<UDPSocket<Handler, MaxDatagramSize>>
{
public:
	enum { maxDatagramSize = MaxDatagramSize };
	static_assert((unsigned)maxDatagramSize < 65507u, "UDP datagrams cannot be larger than 65507 bytes");

	UDPSocket(ba::io_service& _io, UDPSocketEvents& _host, bi::udp::endpoint _endpoint): m_host(_host), m_endpoint(_endpoint), m_socket(_io) { m_started.store(false); m_closed.store(true); };

	UDPSocket(ba::io_service& _io, UDPSocketEvents& _host, unsigned _port): m_host(_host), m_endpoint(bi::udp::v4(), _port), m_socket(_io) { m_started.store(false); m_closed.store(true); };
	virtual ~UDPSocket() { disconnect(); }

	void connect();

	bool send(UDPDatagram const& _datagram);


	bool isOpen() { return !m_closed; }

	void disconnect() { disconnectWithError(boost::asio::error::connection_reset); }

protected:
	void doRead();

	void doWrite();

	void disconnectWithError(boost::system::error_code _ec);

	std::atomic<bool> m_started;	
	std::atomic<bool> m_closed;					

	UDPSocketEvents& m_host;						
	bi::udp::endpoint m_endpoint;					

	Mutex x_sendQ;
	std::deque<UDPDatagram> m_sendQ;				
	std::array<byte, maxDatagramSize> m_recvData;	
	bi::udp::endpoint m_recvEndpoint;				
	bi::udp::socket m_socket;						

	Mutex x_socketError;							
	boost::system::error_code m_socketError;		
};

template <typename Handler, unsigned MaxDatagramSize>
void UDPSocket<Handler, MaxDatagramSize>::connect()
{
	bool expect = false;
	if (!m_started.compare_exchange_strong(expect, true))
		return;

	m_socket.open(bi::udp::v4());
	try
	{
		m_socket.bind(m_endpoint);
	}
	catch (...)
	{
		m_socket.bind(bi::udp::endpoint(bi::udp::v4(), m_endpoint.port()));
	}

	Guard l(x_sendQ);
	m_sendQ.clear();

	m_closed = false;
	doRead();
}

template <typename Handler, unsigned MaxDatagramSize>
bool UDPSocket<Handler, MaxDatagramSize>::send(UDPDatagram const& _datagram)
{
	if (m_closed)
		return false;

	Guard l(x_sendQ);
	m_sendQ.push_back(_datagram);
	if (m_sendQ.size() == 1)
		doWrite();

	return true;
}

template <typename Handler, unsigned MaxDatagramSize>
void UDPSocket<Handler, MaxDatagramSize>::doRead()
{
	if (m_closed)
		return;

	auto self(UDPSocket<Handler, MaxDatagramSize>::shared_from_this());
	m_socket.async_receive_from(boost::asio::buffer(m_recvData), m_recvEndpoint, [this, self](boost::system::error_code _ec, size_t _len)
	{
		if (m_closed)
			return disconnectWithError(_ec);
		
		if (_ec != boost::system::errc::success)
			clog(NetWarn) << "Receiving UDP message failed. " << _ec.value() << ":" << _ec.message();

		if (_len)
			m_host.onReceived(this, m_recvEndpoint, bytesConstRef(m_recvData.data(), _len));
		doRead();
	});
}

template <typename Handler, unsigned MaxDatagramSize>
void UDPSocket<Handler, MaxDatagramSize>::doWrite()
{
	if (m_closed)
		return;

	const UDPDatagram& datagram = m_sendQ[0];
	auto self(UDPSocket<Handler, MaxDatagramSize>::shared_from_this());
	bi::udp::endpoint endpoint(datagram.endpoint());
	m_socket.async_send_to(boost::asio::buffer(datagram.data), endpoint, [this, self, endpoint](boost::system::error_code _ec, std::size_t)
	{
		if (m_closed)
			return disconnectWithError(_ec);
		
		if (_ec != boost::system::errc::success)
			clog(NetWarn) << "Failed delivering UDP message. " << _ec.value() << ":" << _ec.message();
		
		Guard l(x_sendQ);
		m_sendQ.pop_front();
		if (m_sendQ.empty())
			return;
		doWrite();
	});
}

template <typename Handler, unsigned MaxDatagramSize>
void UDPSocket<Handler, MaxDatagramSize>::disconnectWithError(boost::system::error_code _ec)
{

	if (!m_started && m_closed && !m_socket.is_open()
		return;

	assert(_ec);
	{
		Guard l(x_socketError);
		if (m_socketError != boost::system::error_code())
			return;
		m_socketError = _ec;
	}
	
	bool expected = true;
	if (!m_started.compare_exchange_strong(expected, false))
		return;

	bool wasClosed = m_closed;
	m_closed = true;

	boost::system::error_code ec;
	m_socket.shutdown(bi::udp::socket::shutdown_both, ec);
	m_socket.close();


	if (wasClosed)
		return;

	m_host.onDisconnected(this);
}

}
}

