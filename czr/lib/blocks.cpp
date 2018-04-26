#include <czr/lib/blocks.hpp>

#include <boost/endian/conversion.hpp>

std::string czr::to_string_hex (uint64_t value_a)
{
	std::stringstream stream;
	stream << std::hex << std::noshowbase << std::setw (16) << std::setfill ('0');
	stream << value_a;
	return stream.str ();
}

bool czr::from_string_hex (std::string const & value_a, uint64_t & target_a)
{
	auto error (value_a.empty ());
	if (!error)
	{
		error = value_a.size () > 16;
		if (!error)
		{
			std::stringstream stream (value_a);
			stream << std::hex << std::noshowbase;
			try
			{
				uint64_t number_l;
				stream >> number_l;
				target_a = number_l;
				if (!stream.eof ())
				{
					error = true;
				}
			}
			catch (std::runtime_error &)
			{
				error = true;
			}
		}
	}
	return error;
}

std::string czr::block::to_json ()
{
	std::string result;
	serialize_json (result);
	return result;
}

czr::block_hash czr::block::hash () const
{
	czr::uint256_union result;
	blake2b_state hash_l;
	auto status (blake2b_init (&hash_l, sizeof (result.bytes)));
	assert (status == 0);

	hashables.hash(hash_l);

	status = blake2b_final (&hash_l, result.bytes.data (), sizeof (result.bytes));
	assert (status == 0);
	return result;
}

czr::block_hashables::block_hashables (czr::account const & account_a, czr::block_hash const & previous_a, czr::amount const & balance_a, czr::uint256_union const & link_a) :
account (account_a),
previous (previous_a),
balance (balance_a),
link (link_a)
{
	//todo:add new fields/////////////////
}

czr::block_hashables::block_hashables (bool & error_a, czr::stream & stream_a)
{
	error_a = czr::read (stream_a, account);
	if (!error_a)
	{
		error_a = czr::read (stream_a, previous);
		if (!error_a)
		{
			error_a = czr::read(stream_a, balance);
			if (!error_a)
			{
				error_a = czr::read(stream_a, link);
			}
		}
	}
}

czr::block_hashables::block_hashables (bool & error_a, boost::property_tree::ptree const & tree_a)
{
	//todo: add new feilds /////////////////
	try
	{
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		error_a = account.decode_account (account_l);
		if (!error_a)
		{
			error_a = previous.decode_hex (previous_l);
			if (!error_a)
			{
				error_a = balance.decode_dec(balance_l);
				if (!error_a)
				{
					error_a = link.decode_account(link_l) && link.decode_hex(link_l);
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}
}

void czr::block_hashables::hash (blake2b_state & hash_a) const
{
	blake2b_update (&hash_a, account.bytes.data (), sizeof (account.bytes));
	blake2b_update (&hash_a, previous.bytes.data (), sizeof (previous.bytes));
	blake2b_update (&hash_a, balance.bytes.data (), sizeof (balance.bytes));
	blake2b_update (&hash_a, link.bytes.data (), sizeof (link.bytes));

	if(witness_list.empty())
		blake2b_update(&hash_a, witness_list_block.bytes.data(), sizeof(witness_list_block.bytes));
	else
	{
		for (auto witness : witness_list)
			blake2b_update(&hash_a, witness.bytes.data(), sizeof(witness.bytes));
	}

	blake2b_update(&hash_a, last_summary_block.bytes.data(), sizeof(last_summary_block.bytes));

	for (auto p : parents)
		blake2b_update(&hash_a, p.bytes.data(), sizeof(p.bytes));

	blake2b_update(&hash_a, data.data(), sizeof(data));
}

czr::block::block (czr::account const & account_a, czr::block_hash const & previous_a, czr::amount const & balance_a, czr::uint256_union const & link_a, czr::raw_key const & prv_a, czr::public_key const & pub_a, uint64_t work_a) :
hashables (account_a, previous_a, balance_a, link_a),
signature (czr::sign_message (prv_a, pub_a, hash ())),
work (work_a)
{
	//todo:add new fields/////////////////
}

czr::block::block (bool & error_a, czr::stream & stream_a) :
hashables (error_a, stream_a)
{
	if (!error_a)
	{
		error_a = czr::read (stream_a, signature);
		if (!error_a)
		{
			error_a = czr::read (stream_a, work);
			boost::endian::big_to_native_inplace (work);
		}
	}
}

czr::block::block (bool & error_a, boost::property_tree::ptree const & tree_a) :
hashables (error_a, tree_a)
{
	if (!error_a)
	{
		try
		{
			auto signature_l (tree_a.get<std::string> ("signature"));
			auto work_l (tree_a.get<std::string> ("work"));
			error_a = czr::from_string_hex(work_l, work);
			if (!error_a)
			{
				error_a = signature.decode_hex(signature_l);
			}
		}
		catch (std::runtime_error const &)
		{
			error_a = true;
		}
	}
}

uint64_t czr::block::block_work () const
{
	return work;
}

void czr::block::block_work_set (uint64_t work_a)
{
	work = work_a;
}

czr::block_hash czr::block::previous () const
{
	return hashables.previous;
}

void czr::block::serialize (czr::stream & stream_a) const
{
	//todo:serialize block///////////////
	write (stream_a, hashables.account);
	write (stream_a, hashables.previous);
	write (stream_a, hashables.balance);
	write (stream_a, hashables.link);
	write (stream_a, signature);
	write (stream_a, boost::endian::native_to_big (work));
}

void czr::block::serialize_json (std::string & string_a) const
{
	//todo:add new feilds///////////////
	boost::property_tree::ptree tree;
	tree.put ("account", hashables.account.to_account ());
	tree.put ("previous", hashables.previous.to_string ());
	tree.put ("balance", hashables.balance.to_string_dec ());
	tree.put ("link", hashables.link.to_string ());
	tree.put ("link_as_account", hashables.link.to_account ());
	std::string signature_l;
	signature.encode_hex (signature_l);
	tree.put ("signature", signature_l);
	tree.put ("work", czr::to_string_hex (work));
	std::stringstream ostream;
	boost::property_tree::write_json (ostream, tree);
	string_a = ostream.str ();
}

bool czr::block::deserialize (czr::stream & stream_a)
{
	//todo:deserialize block///////////////
	auto error (read (stream_a, hashables.account));
	if (!error)
	{
		error = read (stream_a, hashables.previous);
		if (!error)
		{
			error = read(stream_a, hashables.balance);
			if (!error)
			{
				error = read(stream_a, hashables.link);
				if (!error)
				{
					error = read(stream_a, signature);
					if (!error)
					{
						error = read(stream_a, work);
						boost::endian::big_to_native_inplace(work);
					}
				}
			}
		}
	}
	return error;
}

bool czr::block::deserialize_json (boost::property_tree::ptree const & tree_a)
{
	auto error (false);
	try
	{
		//todo:add new feilds///////////////
		auto account_l (tree_a.get<std::string> ("account"));
		auto previous_l (tree_a.get<std::string> ("previous"));
		auto balance_l (tree_a.get<std::string> ("balance"));
		auto link_l (tree_a.get<std::string> ("link"));
		auto work_l (tree_a.get<std::string> ("work"));
		auto signature_l (tree_a.get<std::string> ("signature"));
		error = hashables.account.decode_account (account_l);
		if (!error)
		{
			error = hashables.previous.decode_hex(previous_l);
			if (!error)
			{
				error = hashables.balance.decode_dec(balance_l);
				if (!error)
				{
					error = hashables.link.decode_account(link_l) && hashables.link.decode_hex(link_l);
					if (!error)
					{
						error = czr::from_string_hex(work_l, work);
						if (!error)
						{
							error = signature.decode_hex(signature_l);
						}
					}
				}
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

void czr::block::visit (czr::block_visitor & visitor_a) const
{
	visitor_a.block (*this);
}

bool czr::block::operator== (czr::block const & other_a) const
{
	return hash() == other_a.hash()
		&& signature == other_a.signature 
		&& work == other_a.work;
}

czr::block_hash czr::block::root () const
{
	return !hashables.previous.is_zero () ? hashables.previous : hashables.account;
}

czr::signature czr::block::block_signature () const
{
	return signature;
}

void czr::block::signature_set (czr::uint512_union const & signature_a)
{
	signature = signature_a;
}

std::unique_ptr<czr::block> czr::deserialize_block_json (boost::property_tree::ptree const & tree_a)
{
	std::unique_ptr<czr::block> result;
	try
	{
		bool error;
		std::unique_ptr<czr::block> obj(new czr::block(error, tree_a));
		if (!error)
		{
			result = std::move(obj);
		}
	}
	catch (std::runtime_error const &)
	{
	}
	return result;
}

std::unique_ptr<czr::block> czr::deserialize_block (czr::stream & stream_a)
{
	std::unique_ptr<czr::block> result;
	bool error;
	std::unique_ptr<czr::block> obj(new czr::block(error, stream_a));
	if (!error)
		result = std::move(obj);

	return result;
}
