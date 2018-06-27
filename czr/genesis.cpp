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
	"exec_timestamp":"1526568538",
	"signature": "9F0C933C8ADE004D808EA1985FA746A7E95BA2A38F867640F53EC8F180BDFE9E2C1268DEAD7C2664F356E37ABA362BC58E46DBA03E523A7B5A19E4B6EB12BB02"
})%%%";

char const * live_genesis_data = R"%%%({
    "from":"czr_1om565pqoa58fejtdcnz1taeuaocynotqdajbadnhoneqtx3xgoaqawtpac5",
    "to":"czr_19rw6416uie15u9qfiyt8s8wr5zjac57c1gmb3bdrz1bo4dgm8gm3quwgrfg",
    "amount":"1000000",
    "previous":"000000000000000000000000000000000000000000000000000000000000",
    "parents":[],
    "witness_list_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "witness_list":[
     "czr_19rw6416uie15u9qfiyt8s8wr5zjac57c1gmb3bdrz1bo4dgm8gm3quwgrfg",
     "czr_1dx7bhufrkjezp619waf8fxaey486oddypua834943tb3squwaots4yexug1",
     "czr_1mq7emka3d1o7gxgn5bera1a1hprxzdego6d8hzspauada3dwggwgbrxibmn",
     "czr_1om565pqoa58fejtdcnz1taeuaocynotqdajbadnhoneqtx3xgoaqawtpac5",
     "czr_1r4k3dktqqf65uj64zhsfq9yekw4on5z4n554q347qwrzwk3cgae9indkmkc",
     "czr_1rasmtxbe1zs5ci1rwto9m7btzhf7qoxo3km7ryfeebedkueg3197os7syfq",
     "czr_1xkiaigais6p1d9t4pgpw8uwj5rp5f7sdzbue98pnwusc185xgyry95ftums",
     "czr_3hm5yqgu5ien17ec4ytnb68ynj9ey361pt81ze9d1yk9qke67sjfch11pkh7",
     "czr_3igubg9qb1fr7uoydq7h8azb1x4i3qkirgb9gdex14fcy11yy8bbekckh5bs",
     "czr_3kbf4urj7uo91ghsq1cgdd3ez86e8eu1sifsyx3b8rzq97b9q9atwkaokya9",
     "czr_3omxq3jmd51ohdnbyea84pz8meemph7n8ywnq1mkpzh3apsj4s9yz9uocbbk",
     "czr_3z1docm8bqeeogpwp7h7x1t5p8m65paqjqm4qn6afiycmdmmuxynimjgau4e"
    ],
    "last_summary":"0000000000000000000000000000000000000000000000000000000000000000",
    "last_summary_block":"0000000000000000000000000000000000000000000000000000000000000000",
    "data":"",
	"exec_timestamp":"1526568538",
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
	block_state.timestamp = block->hashables.exec_timestamp;
	block_state.from_state = 0;
	block_state.to_state = 0;
	store_a.block_state_put(transaction_a, block_hash, block_state);

	//mci
	store_a.main_chain_put(transaction_a, *block_state.main_chain_index, block_hash);
	store_a.mci_block_put(transaction_a, czr::mci_block_key(*block_state.main_chain_index, block_hash));

	//free
	store_a.free_put(transaction_a, czr::free_key(block_state.witnessed_level, block_state.level, block_hash));

	//to account state
	czr::account_state to_state(block->hashables.to, block_hash, 0, block->hashables.amount);
	store_a.account_state_put(transaction_a, to_state.hash(), to_state);
	store_a.latest_account_state_put(transaction_a, block->hashables.to, to_state);


	//witness list
	czr::witness_list_info wl_info(block->hashables.witness_list);
	store_a.block_witness_list_put(transaction_a, block_hash, wl_info);
	czr::witness_list_key wl_key(wl_info.hash(), *block_state.main_chain_index);
	store_a.witness_list_hash_block_put(transaction_a, wl_key, block_hash);

	//summary hash
	std::vector<czr::summary_hash> p_summary_hashs; //no parents
	std::set<czr::summary_hash> summary_skiplist; //no skiplist
	czr::summary_hash summary_hash = czr::summary::gen_summary_hash(block_hash, p_summary_hashs, summary_skiplist,
		block_state.is_fork, block_state.is_invalid, block_state.is_fail, block_state.from_state, block_state.to_state);
	store_a.block_summary_put(transaction_a, block_hash, summary_hash);
	store_a.summary_block_put(transaction_a, summary_hash, block_hash);
}

czr::block_hash czr::genesis::block_hash(0);

