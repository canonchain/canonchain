cmake_minimum_required (VERSION 2.8.11)
project (czr)

set (VERSION_MAJOR "1")
set (VERSION_MINOR "0")

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

set(CMAKE_INSTALL_RPATH "\$ORIGIN/../lib:\$ORIGIN/")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set (CANONCHAIN_SECURE_RPC OFF CACHE BOOL "")

option(CANONCHAIN_ASAN_INT "Enable ASan+UBSan+Integer overflow" OFF)
option(CANONCHAIN_ASAN "Enable ASan+UBSan" OFF)
option(CANONCHAIN_SIMD_OPTIMIZATIONS "Enable CPU-specific SIMD optimizations (SSE/AVX or NEON, e.g.)" OFF)
set (BOOST_CUSTOM OFF CACHE BOOL "")

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if (WIN32)
	set (PLATFORM_COMPILE_FLAGS "-DBOOST_SPIRIT_THREADSAFE -D_WIN32_WINNT=0x0600 -DWINVER=0x0600 -DWIN32_LEAN_AND_MEAN")
	set (BLAKE2_IMPLEMENTATION "blake2/blake2b.c")
else (WIN32)
	set (PLATFORM_COMPILE_FLAGS "-DBOOST_SPIRIT_THREADSAFE -Werror=switch -fPIC")
	if (CANONCHAIN_ASAN)
		set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -fsanitize=address,undefined -DED25519_NO_INLINE_ASM")
	elseif (CANONCHAIN_ASAN_INT)
		set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -fsanitize=address,undefined,integer -DED25519_NO_INLINE_ASM")
	elseif (CANONCHAIN_TSAN)
		set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -fsanitize=thread -DED25519_NO_INLINE_ASM")
	endif()

	IF (CMAKE_SYSTEM_PROCESSOR MATCHES "^(i.86|x86(_64)?)$")
		if (CANONCHAIN_SIMD_OPTIMIZATIONS)
			set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -msse4")
		elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
			set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -msse2")
		endif()

		set (BLAKE2_IMPLEMENTATION "blake2/blake2b.c")
		if (ENABLE_AVX2)
			set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -mavx2 -mbmi -mbmi2")
			if (PERMUTE_WITH_GATHER)
				set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -DPERMUTE_WITH_GATHER")
			elseif (PERMUTE_WITH_SHUFFLES)
				set (PLATFORM_COMPILE_FLAGS "${PLATFORM_COMPILE_FLAGS} -DPERMUTE_WITH_SHUFFLES")
			endif()
		endif()
	else()
		set (BLAKE2_IMPLEMENTATION "blake2/blake2b-ref.c")
	endif()
endif (WIN32)

if (WIN32)
	set (PLATFORM_C_FLAGS "/std=c11")
else (WIN32)
	set (PLATFORM_C_FLAGS "-std=c11")
endif (WIN32)

if (WIN32)
	set (PLATFORM_CXX_FLAGS "/bigobj")
else (WIN32)
	set (PLATFORM_CXX_FLAGS "-std=c++14")
endif (WIN32)

if (WIN32)
	set (PLATFORM_GUI_TARGET_PROPERTIES WIN32)
else (WIN32)
	set (PLATFORM_GUI_TARGET_PROPERTIES "")
endif (WIN32)

if (APPLE)
	set (PLATFORM_LINK_FLAGS "-framework Foundation -framework OpenCL")
elseif (WIN32)
	set (PLATFORM_LINK_FLAGS "")
else ()
	set (PLATFORM_LINK_FLAGS "-static-libgcc -static-libstdc++")
	if (CANONCHAIN_ASAN)
		set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize=address,undefined")
	elseif (CANONCHAIN_ASAN_INT)
		set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize=address,undefined,integer")
	elseif (CANONCHAIN_TSAN)
		set (PLATFORM_LINK_FLAGS "${PLATFORM_LINK_FLAGS} -fsanitize=thread")
	endif()
endif (APPLE)

if (CANONCHAIN_SECURE_RPC)
	find_package (OpenSSL 1.0 EXACT REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})
	add_definitions (-DCANONCHAIN_SECURE_RPC)
	message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
	message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")
	message("OpenSSL lib: ${OPENSSL_SSL_LIBRARY}")
	message("Crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
else ()
	set (OPENSSL_LIBRARIES "")
endif (CANONCHAIN_SECURE_RPC)

include_directories (${CMAKE_SOURCE_DIR})

set(Boost_USE_STATIC_LIBS        ON)
set(Boost_USE_MULTITHREADED      ON)

if (BOOST_CUSTOM)
    list(APPEND CMAKE_MODULE_PATH ".\\" ${CMAKE_SOURCE_PATH})
endif (BOOST_CUSTOM)

find_package (Boost 1.66.0 REQUIRED COMPONENTS date_time filesystem system log log_setup thread program_options regex chrono atomic)
include_directories (${Boost_INCLUDE_DIR})

add_library (ed25519
	ed25519-donna/ed25519-donna-portable.h
	ed25519-donna/ed25519-hash-custom.h
	ed25519-donna/ed25519-randombytes-custom.h
	ed25519-donna/ed25519.h
	ed25519-donna/ed25519.c)

include_directories("${CMAKE_SOURCE_DIR}/phc-winner-argon2/include")
include_directories("${CMAKE_SOURCE_DIR}/phc-winner-argon2/src")
include_directories("${CMAKE_SOURCE_DIR}/blake2")

include_directories("${CMAKE_SOURCE_DIR}/czr/p2p")


if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
	set (ARGON_CORE phc-winner-argon2/src/opt.c)
else ()
	set (ARGON_CORE phc-winner-argon2/src/ref.c)
endif ()

set (BUILD_SHARED OFF CACHE BOOL "")
set (USE_INTERMEDIATE_OBJECTS_TARGET OFF CACHE BOOL "")
if (CRYPTOPP_CUSTOM OR NOT CANONCHAIN_SIMD_OPTIMIZATIONS)
	set (CRYPTOPP_LIBRARY cryptopp)
	add_library (cryptopp
	cryptopp/algparam.cpp
	cryptopp/asn.cpp
	cryptopp/basecode.cpp
	cryptopp/cpu.cpp
	cryptopp/cryptlib.cpp
	cryptopp/default.cpp
	cryptopp/des.cpp
	cryptopp/dessp.cpp
	cryptopp/dll.cpp
	cryptopp/ec2n.cpp
	cryptopp/ecp.cpp
	cryptopp/filters.cpp
	cryptopp/fips140.cpp
	cryptopp/gcm.cpp
	cryptopp/gf2n.cpp
	cryptopp/gfpcrypt.cpp
	cryptopp/hex.cpp
	cryptopp/hmac.cpp
	cryptopp/hrtimer.cpp
	cryptopp/integer.cpp
	cryptopp/iterhash.cpp
	cryptopp/misc.cpp
	cryptopp/modes.cpp
	cryptopp/mqueue.cpp
	cryptopp/nbtheory.cpp
	cryptopp/oaep.cpp
	cryptopp/osrng.cpp
	cryptopp/pubkey.cpp
	cryptopp/queue.cpp
	cryptopp/randpool.cpp
	cryptopp/rdtables.cpp
	cryptopp/rijndael.cpp
	cryptopp/rng.cpp
	cryptopp/sha.cpp
	cryptopp/simple.cpp
	cryptopp/winpipes.cpp)
	set_target_properties (cryptopp PROPERTIES COMPILE_FLAGS "${PLATFORM_CXX_FLAGS} ${PLATFORM_COMPILE_FLAGS}")
else ()
	set (CRYPTOPP_LIBRARY cryptopp-static)
	add_subdirectory (cryptopp)
endif ()

add_library (argon2
	phc-winner-argon2/src/argon2.c
	phc-winner-argon2/include/argon2.h
	phc-winner-argon2/src/core.c
	phc-winner-argon2/src/thread.c
	phc-winner-argon2/src/encoding.c
	${ARGON_CORE})

add_library (xxhash
	xxhash/xxhash.c
	xxhash/xxhash.h)

add_library (lmdb
	lmdb/libraries/liblmdb/lmdb.h
	lmdb/libraries/liblmdb/mdb.c
	lmdb/libraries/liblmdb/midl.c)

add_library (blake2
	blake2/blake2-config.h
	blake2/blake2-impl.h
	blake2/blake2.h
	${BLAKE2_IMPLEMENTATION})

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	set (PLATFORM_LIB_SOURCE czr/plat/default/priority.cpp)
	set (PLATFORM_SECURE_SOURCE czr/plat/osx/working.mm)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set (PLATFORM_LIB_SOURCE czr/plat/windows/priority.cpp)
	set (PLATFORM_SECURE_SOURCE czr/plat/windows/working.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	set (PLATFORM_LIB_SOURCE czr/plat/linux/priority.cpp)
	set (PLATFORM_SECURE_SOURCE czr/plat/posix/working.cpp)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
	set (PLATFORM_LIB_SOURCE czr/plat/default/priority.cpp)
	set (PLATFORM_SECURE_SOURCE czr/plat/posix/working.cpp)
else ()
	error ("Unknown platform: ${CMAKE_SYSTEM_NAME}")
endif ()
	
if (CANONCHAIN_SECURE_RPC)
	set (SECURE_RPC_SOURCE czr/node/rpc_secure.cpp czr/node/rpc_secure.hpp)
endif ()

add_library (secure
	${PLATFORM_SECURE_SOURCE}
	czr/config.hpp
	czr/common.cpp
	czr/common.hpp
	czr/blockstore.cpp
	czr/blockstore.hpp
	czr/genesis.cpp
	czr/genesis.hpp
	czr/graph.cpp
	czr/graph.hpp
	czr/ledger.cpp
	czr/ledger.hpp
	czr/node/utility.cpp
	czr/node/utility.hpp)

SET (CZR_LIB_SOURCES
	${PLATFORM_LIB_SOURCE}
	czr/lib/blocks.cpp
	czr/lib/blocks.hpp
	czr/lib/interface.cpp
	czr/lib/numbers.cpp
	czr/lib/numbers.hpp
	czr/lib/utility.hpp)

add_library (czr_lib SHARED ${CZR_LIB_SOURCES})
add_library (czr_lib_static STATIC ${CZR_LIB_SOURCES})

add_library (node
	${PLATFORM_NODE_SOURCE}
	${SECURE_RPC_SOURCE}
	czr/node/common.cpp
	czr/node/common.hpp
	czr/node/chain.hpp
	czr/node/chain.cpp
	czr/node/composer.hpp
	czr/node/composer.cpp
	czr/node/node.hpp
	czr/node/node.cpp
	czr/node/witness.hpp
	czr/node/witness.cpp
	czr/node/rpc.hpp
	czr/node/rpc.cpp
	czr/node/validation.hpp
	czr/node/validation.cpp
	czr/node/wallet.hpp
	czr/node/wallet.cpp
	czr/node/working.hpp)
	
add_library (rlp
	czr/rlp/Common.h
	czr/rlp/CommonData.cpp
	czr/rlp/CommonData.h
	czr/rlp/Exceptions.h
	czr/rlp/FixedHash.cpp
	czr/rlp/FixedHash.h
	czr/rlp/RLP.cpp
	czr/rlp/RLP.h
	czr/rlp/vector_ref.h)

add_library (p2p
	${PLATFORM_P2P_SOURCE}
	czr/p2p/common.hpp
	czr/p2p/common.cpp
	czr/p2p/frame_coder.hpp
	czr/p2p/frame_coder.cpp
	czr/p2p/peer.hpp
	czr/p2p/peer.cpp
	czr/p2p/host.hpp
	czr/p2p/host.cpp
	czr/p2p/node_discover.hpp
	czr/p2p/node_discover.cpp
	czr/p2p/node_table.hpp
	czr/p2p/node_table.cpp)


SET (ACTIVE_NETWORK czr_live_network CACHE STRING "Selects which network parameters are used")
set_property (CACHE ACTIVE_NETWORK PROPERTY STRINGS czr_test_network czr_beta_network czr_live_network)

add_executable (czr_node
	czr/czr_node/daemon.cpp
	czr/czr_node/daemon.hpp
	czr/czr_node/entry.cpp)

set_target_properties (argon2 PROPERTIES COMPILE_FLAGS "${PLATFORM_C_FLAGS} ${PLATFORM_COMPILE_FLAGS}")
set_target_properties (blake2 PROPERTIES COMPILE_FLAGS "${PLATFORM_C_FLAGS} ${PLATFORM_COMPILE_FLAGS} -D__SSE2__")
set_target_properties (ed25519 PROPERTIES COMPILE_FLAGS "${PLATFORM_C_FLAGS} ${PLATFORM_COMPILE_FLAGS} -DED25519_CUSTOMHASH -DED25519_CUSTOMRNG")
set_target_properties (secure node rlp p2p czr_node czr_lib czr_lib_static PROPERTIES COMPILE_FLAGS "${PLATFORM_CXX_FLAGS} ${PLATFORM_COMPILE_FLAGS} -DQT_NO_KEYWORDS -DACTIVE_NETWORK=${ACTIVE_NETWORK} -DCANONCHAIN_VERSION_MAJOR=${VERSION_MAJOR} -DCANONCHAIN_VERSION_MINOR=${VERSION_MINOR} -DBOOST_ASIO_HAS_STD_ARRAY=1 -DBOOST_LOG_DYN_LINK")
set_target_properties (secure node czr_node PROPERTIES LINK_FLAGS "${PLATFORM_LINK_FLAGS}")

if (WIN32)
	set (PLATFORM_LIBS Ws2_32 mswsock iphlpapi ntdll)
else (WIN32)
	set (PLATFORM_LIBS pthread ${CMAKE_DL_LIBS})
endif (WIN32)

target_link_libraries (czr_lib ed25519 xxhash blake2 ${CRYPTOPP_LIBRARY})
target_link_libraries (czr_lib_static ed25519 xxhash blake2 ${CRYPTOPP_LIBRARY})

target_link_libraries (czr_node node secure lmdb ed25519 czr_lib_static argon2 ${OPENSSL_LIBRARIES} ${CRYPTOPP_LIBRARY} ${Boost_ATOMIC_LIBRARY} ${Boost_CHRONO_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_DATE_TIME_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_LOG_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_LOG_SETUP_LIBRARY} ${Boost_THREAD_LIBRARY} ${PLATFORM_LIBS})