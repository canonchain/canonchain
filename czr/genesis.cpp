#include <czr/genesis.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

char const * test_genesis_data = R"%%%({
    "from":"czr_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
    "to":"czr_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh01",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh02",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh03",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh04",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh05",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh06",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh07",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh08",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh09",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh10", 
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh11",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh12"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"work": "62f05417dd3fb691",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

char const * beta_genesis_data = R"%%%({
    "from":"czr_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
    "to":"czr_11rjpbh1t9ixgwkdqbfxcawobwgusz13sg595ocytdbkrxcbzekkcqkc3dn1",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh01",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh02",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh03",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh04",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh05",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh06",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh07",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh08",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh09",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh10",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh11",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuoh12"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"work": "62f05417dd3fb691",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

char const * live_genesis_data = R"%%%({
    "from":"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
    "to":"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
		"czr_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"work": "62f05417dd3fb691",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

void czr::genesis::try_initialize(MDB_txn * transaction_a, czr::block_store & store_a)
{
	bool exists(!store_a.genesis_hash_get(transaction_a, block_hash));
	if (exists)
		return;

	auto genesis_data(czr::czr_network == czr::czr_networks::czr_test_network ? test_genesis_data : czr::czr_network == czr::czr_networks::czr_beta_network ? beta_genesis_data: live_genesis_data);
	std::stringstream istream(genesis_data);

	boost::property_tree::ptree tree;
	boost::property_tree::read_json(istream, tree);
	bool error;
	std::unique_ptr<czr::block> block(new czr::block(error, tree));
	if (error)
		throw std::runtime_error("deserialize genesis block error");

	block_hash = block->hash();
	store_a.genesis_hash_put(transaction_a, block_hash);
	store_a.block_put(transaction_a, block_hash, *block);

	//block state
	czr::block_state block_state;
	block_state.is_fork = false;
	block_state.is_invalid = false;
	block_state.is_fail = false;
	block_state.is_free = true;
	block_state.is_on_main_chain = 1;
	block_state.main_chain_index = 0;
	block_state.latest_included_mc_index = boost::none;
	block_state.is_stable = 1;
	block_state.level = 0;
	block_state.witnessed_level = 0;
	block_state.best_parent = 0;
	block_state.creation_date = std::chrono::system_clock::now(); //todo:
	block_state.from_state = 0;
	block_state.to_state = 0;
	store_a.block_state_put(transaction_a, block_hash, block_state);

	//to account state
	czr::account_state to_state(block->hashables.to, block_hash, 0, block->hashables.amount);
	store_a.account_state_put(transaction_a, to_state.hash(), to_state);

	//witness list
	czr::witness_list_info wl_info(block->hashables.witness_list);
	store_a.block_witnesslist_put(transaction_a, block_hash, wl_info);
	auto wl_hash(wl_info.hash());
	if (!store_a.witnesslisthash_block_exists(transaction_a, wl_hash))
	{
		store_a.witnesslisthash_block_put(transaction_a, wl_hash, block_hash);
	}

	//summary hash
	std::vector<czr::summary_hash> p_summary_hashs; //no parents
	std::set<czr::summary_hash> summary_skiplist; //no skiplist
	czr::summary_hash summary_hash = czr::summary::gen_summary_hash(block_hash, p_summary_hashs, summary_skiplist,
		block_state.is_fork, block_state.is_invalid, block_state.is_fail, block_state.from_state, block_state.to_state);
	store_a.block_summary_put(transaction_a, block_hash, summary_hash);
	store_a.summary_block_put(transaction_a, summary_hash, block_hash);
}

czr::block_hash czr::genesis::block_hash(0);

