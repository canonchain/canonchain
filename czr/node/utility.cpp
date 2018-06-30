#include "utility.hpp"
#include <czr/node/utility.hpp>
#include <czr/node/working.hpp>

#include <lmdb/libraries/liblmdb/lmdb.h>

#include <ed25519-donna/ed25519.h>

boost::filesystem::path czr::working_path()
{
	auto result(czr::app_path());
	switch (czr::czr_network)
	{
	case czr::czr_networks::czr_test_network:
		result /= "CanonchainTest";
		break;
	case czr::czr_networks::czr_beta_network:
		result /= "CanonchainBeta";
		break;
	case czr::czr_networks::czr_live_network:
		result /= "Canonchain";
		break;
	}
	return result;
}

boost::filesystem::path czr::unique_path()
{
	auto result(working_path() / boost::filesystem::unique_path());
	return result;
}

czr::mdb_env::mdb_env(bool & error_a, boost::filesystem::path const & path_a, int max_dbs)
{
	boost::system::error_code error;
	if (path_a.has_parent_path())
	{
		boost::filesystem::create_directories(path_a.parent_path(), error);
		if (!error)
		{
			auto status1(mdb_env_create(&environment));
			assert(status1 == 0);
			//std::cerr << status1 << std::endl;

			auto status2(mdb_env_set_maxdbs(environment, max_dbs));
			assert(status2 == 0);
			//std::cerr << status2 << std::endl;

			auto status3(mdb_env_set_mapsize(environment, 1ULL * 500 * 1024 * 1024 * 1024)); // 0.5 Terabyte
			assert(status3 == 0);
			//std::cerr << status3 << std::endl;

			// It seems if there's ever more threads than mdb_env_set_maxreaders has read slots available, we get failures on transaction creation unless MDB_NOTLS is specified
			// This can happen if something like 256 io_threads are specified in the node config
			auto status4(mdb_env_open(environment, path_a.string().c_str(), MDB_NOSUBDIR | MDB_NOTLS, 00600));
			error_a = status4 != 0;
			//std::cerr << status4 << std::endl;
		}
		else
		{
			error_a = true;
			environment = nullptr;
		}
	}
	else
	{
		error_a = true;
		environment = nullptr;
	}
}

czr::mdb_env::~mdb_env()
{
	if (environment != nullptr)
	{
		mdb_env_close(environment);
	}
}

czr::mdb_env::operator MDB_env * () const
{
	return environment;
}

czr::mdb_val::mdb_val() :
	value({ 0, nullptr })
{
}

czr::mdb_val::mdb_val(MDB_val const & value_a) :
	value(value_a)
{
}

czr::mdb_val::mdb_val(size_t size_a, void * data_a) :
	value({ size_a, data_a })
{
}

czr::mdb_val::mdb_val(uint64_t const & val_a) :
	mdb_val(sizeof(val_a), const_cast<uint64_t *> (&val_a))
{
}

czr::mdb_val::mdb_val(czr::uint128_union const & val_a) :
	mdb_val(sizeof(val_a), const_cast<czr::uint128_union *> (&val_a))
{
}

czr::mdb_val::mdb_val(czr::uint256_union const & val_a) :
	mdb_val(sizeof(val_a), const_cast<czr::uint256_union *> (&val_a))
{
}

void * czr::mdb_val::data() const
{
	return value.mv_data;
}

size_t czr::mdb_val::size() const
{
	return value.mv_size;
}

uint64_t czr::mdb_val::uint64() const
{
	uint64_t result(0);
	assert(size() == sizeof(result));
	result = *(uint64_t*)data();
	return result;
}

czr::uint256_union czr::mdb_val::uint256() const
{
	czr::uint256_union result;
	assert(size() == sizeof(result));
	std::copy(reinterpret_cast<uint8_t const *> (data()), reinterpret_cast<uint8_t const *> (data()) + sizeof(result), result.bytes.data());
	return result;
}


czr::mdb_val::operator MDB_val * () const
{
	// Allow passing a temporary to a non-c++ function which doesn't have constness
	return const_cast<MDB_val *> (&value);
};

czr::mdb_val::operator MDB_val const & () const
{
	return value;
}

czr::transaction::transaction(czr::mdb_env & environment_a, MDB_txn * parent_a, bool write) :
	environment(environment_a),
	is_abort(false)
{
	auto status(mdb_txn_begin(environment_a, parent_a, write ? 0 : MDB_RDONLY, &handle));
	assert(status == 0);
}

czr::transaction::~transaction()
{
	if (!is_abort)
	{
		auto status(mdb_txn_commit(handle));
		assert(status == 0);
	}
}

void czr::transaction::abort()
{
	is_abort = true;
	mdb_txn_abort(handle);
}

czr::transaction::operator MDB_txn * () const
{
	return handle;
}

void czr::open_or_create(std::fstream & stream_a, std::string const & path_a)
{
	stream_a.open(path_a, std::ios_base::in);
	if (stream_a.fail())
	{
		stream_a.open(path_a, std::ios_base::out);
	}
	stream_a.close();
	stream_a.open(path_a, std::ios_base::in | std::ios_base::out);
}