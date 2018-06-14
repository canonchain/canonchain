#include "handshake.hpp"

using namespace czr::p2p;

handshake_message::handshake_message(uint16_t const & version_a, czr::czr_networks const & network_a, hash256 const & nonce_a):
	version(version_a),
	network(network_a),
	nonce(nonce_a)
{
}

handshake_message::handshake_message(dev::RLP const & r)
{
	if (r.itemCount() != 3)
		throw std::runtime_error("invalid handshake_message rlp format");

	version = (uint16_t)r[0];
	network = (czr::czr_networks)r[1].toInt<uint8_t>();
	nonce = (hash256)r[2];
}

void handshake_message::stream_RLP(dev::RLPStream & s)
{
	s.appendList(3) << version << (uint8_t)network << nonce;
}

ack_message::ack_message(node_id const & node_id_a, czr::signature const & nonce_sig_a, std::list<capability_desc> const & cap_descs_a):
	id(node_id_a),
	nonce_sig(nonce_sig_a),
	cap_descs(cap_descs_a)
{
}

ack_message::ack_message(dev::RLP const & r)
{
	if (r.itemCount() != 3)
		throw std::runtime_error("invalid ack_message rlp format");

	id = (node_id)r[0];
	nonce_sig = (czr::signature)r[1];
	for (auto const & i : r[2])
		cap_descs.push_back(capability_desc(i));
}

void ack_message::stream_RLP(dev::RLPStream & s)
{
	s.appendList(3) << id << nonce_sig;
	s.appendList(cap_descs.size());
	for (auto & desc : cap_descs)
		desc.stream_RLP(s);
}
