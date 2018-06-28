
#include <czr/node/common.hpp>
#include <czr/node/wallet.hpp>

czr::joint_message::joint_message (std::shared_ptr<czr::block> block_a) :
block (block_a)
{
}

czr::joint_message::joint_message(bool & error_a, dev::RLP const & r)
{
	if (error_a)
		return;

	error_a = r.itemCount() != 1 && r.itemCount() != 8;
	if (error_a)
		return;

	block = std::make_shared<czr::block>(error_a, r[0]);
	if (error_a)
		return;

	if (r.itemCount() > 1)
	{
		summary_hash = (czr::summary_hash)r[1];
		dev::RLP const & sk_list_rlp = r[2];
		block_skiplist.reserve(sk_list_rlp.itemCount());
		for (dev::RLP const & sk : sk_list_rlp)
			block_skiplist.push_back((czr::block_hash)sk);
		is_fork = (bool)r[3];
		is_invalid = (bool)r[4];
		is_fail = (bool)r[5];
		from_state = (czr::account_state_hash)r[6];
		to_state = (czr::account_state_hash)r[7];
	}
}

void czr::joint_message::stream_RLP(dev::RLPStream & s) const
{
	summary_hash.is_zero() ? s.appendList(1): s.appendList(8);
	block->stream_RLP(s);
	if (!summary_hash.is_zero())
	{
		s << summary_hash;
		s.appendList(block_skiplist.size());
		for (czr::block_hash sk : block_skiplist)
			s << sk;
		s << is_fork << is_invalid << is_fail;
		s << from_state << to_state;
	}
}

bool czr::parse_port(std::string const & string_a, uint16_t & port_a)
{
	bool result;
	size_t converted;
	port_a = std::stoul(string_a, &converted);
	result = converted != string_a.size() || converted > std::numeric_limits<uint16_t>::max();
	return result;
}
