#pragma once

#include <atomic>
#include <string>
#include <set>
#include <vector>

// Make sure boost/asio.hpp is included before windows.h.
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>

namespace ba = boost::asio;
namespace bi = boost::asio::ip;

namespace czr
{

class RLP;
class RLPStream;

namespace p2p
{

extern const unsigned c_protocolVersion;
extern const unsigned c_defaultIPPort;

class NodeIPEndpoint;
class Node;
extern const NodeIPEndpoint UnspecifiedNodeIPEndpoint;
extern const Node UnspecifiedNode;

using NodeID = h512;

bool is_private_address(bi::address const& address_to_check);

bool is_private_address(std::string const& address_to_check);

bool is_localHost_address(bi::address const& address_to_check);

bool is_localHost_address(std::string const& address_to_check);

bool is_public_address(bi::address const& address_to_check);

bool is_public_address(std::string const& address_to_check);


enum PacketType
{
	HelloPacket = 0,
	DisconnectPacket,
	PingPacket,
	PongPacket,
	GetPeersPacket,
	PeersPacket,
	UserPacket = 0x10
};

enum DisconnectReason
{
	DisconnectRequested = 0,
	TCPError,
	BadProtocol,
	UselessPeer,
	TooManyPeers,
	DuplicatePeer,
	IncompatibleProtocol,
	NullIdentity,
	ClientQuit,
	UnexpectedIdentity,
	LocalIdentity,
	PingTimeout,
	UserReason = 0x10,
	NoDisconnect = 0xffff
};

inline bool is_permanent_problem(DisconnectReason _r)
{
	switch (_r)
	{
	case DuplicatePeer:
	case IncompatibleProtocol:
	case NullIdentity:
	case UnexpectedIdentity:
	case LocalIdentity:
		return true;
	default:
		return false;
	}
}

std::string reasonOf(DisconnectReason _r);

using CapDesc = std::pair<std::string, u256>;
using CapDescSet = std::set<CapDesc>;
using CapDescs = std::vector<CapDesc>;

struct PeerSessionInfo
{
	NodeID const id;
	std::string const clientVersion;
	std::string const host;
	unsigned short const port;
	std::chrono::steady_clock::duration lastPing;
	std::set<CapDesc> const caps;
	unsigned socketId;
	std::map<std::string, std::string> notes;
	unsigned const protocolVersion;
};

using PeerSessionInfos = std::vector<PeerSessionInfo>;

enum class PeerType
{
	Optional,
	Required
};


class NodeIPEndpoint
{
public:
	enum RLPAppend
	{
		StreamList,
		StreamInline
	};
	
	static bool test_allowLocal;

	NodeIPEndpoint() = default;
	NodeIPEndpoint(bi::address _addr, uint16_t _udp, uint16_t _tcp): address(_addr), udpPort(_udp), tcpPort(_tcp) {}
	NodeIPEndpoint(RLP const& _r) { interpretRLP(_r); }

	operator bi::udp::endpoint() const { return bi::udp::endpoint(address, udpPort); }
	operator bi::tcp::endpoint() const { return bi::tcp::endpoint(address, tcpPort); }
	
	operator bool() const { return !address.is_unspecified() && udpPort > 0 && tcpPort > 0; }
	
	bool isAllowed() const { return NodeIPEndpoint::test_allowLocal ? !address.is_unspecified() : isPublicAddress(address); }

	bool operator==(NodeIPEndpoint const& _cmp) const {
		return address == _cmp.address && udpPort == _cmp.udpPort && tcpPort == _cmp.tcpPort;
 	}
	bool operator!=(NodeIPEndpoint const& _cmp) const {
		return !operator==(_cmp);
 	}
	
	void streamRLP(RLPStream& _s, RLPAppend _append = StreamList) const;
	void interpretRLP(RLP const& _r);

	bi::address address;
	uint16_t udpPort = 0;
	uint16_t tcpPort = 0;
};

struct NodeSpec
{
	NodeSpec() {}

	NodeSpec(std::string const& _user);

	NodeSpec(std::string const& _addr, uint16_t _port, int _udpPort = -1):
		m_address(_addr),
		m_tcpPort(_port),
		m_udpPort(_udpPort == -1 ? _port : (uint16_t)_udpPort)
	{}

	NodeID id() const { return m_id; }

	NodeIPEndpoint nodeIPEndpoint() const;

	std::string enode() const;

private:
	std::string m_address;
	uint16_t m_tcpPort = 0;
	uint16_t m_udpPort = 0;
	NodeID m_id;
};

class Node
{
public:
	Node() = default;
	virtual ~Node() = default;
	Node(Node const&);
	Node(Public _publicKey, NodeIPEndpoint const& _ip, PeerType _peerType = PeerType::Optional): id(_publicKey), endpoint(_ip), peerType(_peerType) {}
	Node(NodeSpec const& _s, PeerType _peerType = PeerType::Optional);

	virtual NodeID const& address() const { return id; }
	virtual Public const& publicKey() const { return id; }
	
	virtual operator bool() const { return (bool)id; }

	NodeID id;

	NodeIPEndpoint endpoint;

	std::atomic<PeerType> peerType{PeerType::Optional};
};

class DeadlineOps
{
	class DeadlineOp
	{
	public:
		DeadlineOp(ba::io_service& _io, unsigned _msInFuture, std::function<void(boost::system::error_code const&)> const& _f): m_timer(new ba::deadline_timer(_io)) { m_timer->expires_from_now(boost::posix_time::milliseconds(_msInFuture)); m_timer->async_wait(_f); }
		~DeadlineOp() { if (m_timer) m_timer->cancel(); }
		
		DeadlineOp(DeadlineOp&& _s): m_timer(_s.m_timer.release()) {}
		DeadlineOp& operator=(DeadlineOp&& _s)
		{
			assert(&_s != this);

			m_timer.reset(_s.m_timer.release());
			return *this;
		}
		
		bool expired() { Guard l(x_timer); return m_timer->expires_from_now().total_nanoseconds() <= 0; }
		void wait() { Guard l(x_timer); m_timer->wait(); }
		
	private:
		std::unique_ptr<ba::deadline_timer> m_timer;
		Mutex x_timer;
	};
	
public:
	DeadlineOps(ba::io_service& _io, unsigned _reapIntervalMs = 100): m_io(_io), m_reapIntervalMs(_reapIntervalMs), m_stopped(false) { reap(); }
	~DeadlineOps() { stop(); }

	void schedule(unsigned _msInFuture, std::function<void(boost::system::error_code const&)> const& _f) { if (m_stopped) return; DEV_GUARDED(x_timers) m_timers.emplace_back(m_io, _msInFuture, _f); }	

	void stop() { m_stopped = true; DEV_GUARDED(x_timers) m_timers.clear(); }

	bool is_stopped() const { return m_stopped; }
	
protected:
	void reap();
	
private:
	ba::io_service& m_io;
	unsigned m_reapIntervalMs;
	
	std::vector<DeadlineOp> m_timers;
	Mutex x_timers;
	
	std::atomic<bool> m_stopped;
};

}
	
std::ostream& operator<<(std::ostream& _out, dev::p2p::NodeIPEndpoint const& _ep);
}


namespace std
{

template <> struct hash<bi::address>
{
	size_t operator()(bi::address const& _a) const
	{
		if (_a.is_v4())
			return std::hash<unsigned long>()(_a.to_v4().to_ulong());
		if (_a.is_v6())
		{
			auto const& range = _a.to_v6().to_bytes();
			return boost::hash_range(range.begin(), range.end());
		}
		if (_a.is_unspecified())
			return static_cast<size_t>(0x3487194039229152ull);  // Chosen by fair dice roll, guaranteed to be random
		return std::hash<std::string>()(_a.to_string());
	}
};

}

