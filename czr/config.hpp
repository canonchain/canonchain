#pragma once

#include <chrono>
#include <cstddef>

namespace czr
{
// Network variants with different genesis blocks and network parameters
enum class czr_networks
{
	// Normal work parameters, secret live key, live IP ports
	czr_live_network = 1,
	// Low work parameters, publicly known genesis key, test IP ports
	czr_test_network = 2,
	// Normal work parameters, secret beta genesis key, beta IP ports
	czr_beta_network = 3,
};
czr::czr_networks const czr_network = czr_networks::ACTIVE_NETWORK;
std::chrono::milliseconds const transaction_timeout = std::chrono::milliseconds (1000);

size_t const witness_count(12);
size_t const max_witness_list_mutations(1);
size_t const majority_of_witnesses(witness_count / 2 + 1);

size_t const max_parents_size(16);
size_t const max_data_size(32000); //32kb

size_t const skiplist_divisor(10);

}
