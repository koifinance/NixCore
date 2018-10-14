# Copyright (c) 2017-2018 The NIX Core developers
# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue tor

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

TOR_LIBS = tor/src/or/libtor.a \
	tor/src/common/libor.a \
	tor/src/common/libor-ctime.a \
	tor/src/common/libor-crypto.a \
	tor/src/common/libor-event.a \
	tor/src/trunnel/libor-trunnel.a \
	tor/src/common/libcurve25519_donna.a \
	tor/src/ext/ed25519/donna/libed25519_donna.a \
	tor/src/ext/ed25519/ref10/libed25519_ref10.a \
	tor/src/ext/keccak-tiny/libkeccak-tiny.a

tor.timestamp: $(wildcard tor/src/or/*.c) $(wildcard tor/src/or/*.h) \
		$(wildcard tor/src/common/*.c) $(wildcard tor/src/common/*.h) \
		$(wildcard tor/src/trunnel/*.c) $(wildcard tor/src/trunnel/*.h) \
		$(wildcard tor/src/ext/*.c) $(wildcard tor/src/ext/*.h)
	@rm -f tor.timestamp.tmp
	@touch tor.timestamp.tmp
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C tor
	@mv -f tor.timestamp.tmp tor.timestamp

$(TOR_LIBS): tor.timestamp
	@if test -f $@; then :; else \
		rm -f tor.timestamp; \
		$(MAKE) $(AM_MAKEFLAGS) tor.timestamp; \
	fi


NIX_INCLUDES=-I$(builddir) $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

NIX_INCLUDES += -I$(srcdir)/secp256k1/include
NIX_INCLUDES += $(UNIVALUE_CFLAGS)

LIBNIX_SERVER=libnix_server.a
LIBNIX_COMMON=libnix_common.a
LIBNIX_CONSENSUS=libnix_consensus.a
LIBNIX_CLI=libnix_cli.a
LIBNIX_UTIL=libnix_util.a
LIBNIX_CRYPTO=crypto/libnix_crypto.a
LIBNIXQT=qt/libnixqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBNIX_ZMQ=libnix_zmq.a
endif
if BUILD_NIX_LIBS
LIBNIXCONSENSUS=libnixconsensus.la
endif
if ENABLE_WALLET
LIBNIX_WALLET=libnix_wallet.a
endif
if ENABLE_USBDEVICE
LIBPARTICL_USBDEVICE=libnix_usbdevice.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBNIX_CRYPTO) \
  $(LIBNIX_UTIL) \
  $(LIBNIX_COMMON) \
  $(LIBNIX_CONSENSUS) \
  $(LIBNIX_SERVER) \
  $(LIBNIX_CLI) \
  $(LIBNIX_WALLET) \
  $(LIBNIX_USBDEVICE) \
  $(LIBNIX_ZMQ)

lib_LTLIBRARIES = $(LIBNIXCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_NIXD
  bin_PROGRAMS += nixd
endif

if BUILD_NIX_UTILS
  bin_PROGRAMS += nix-cli nix-tx
endif

.PHONY: FORCE check-symbols check-security
# nix core #
NIX_CORE_H = \
  addrdb.h \
  addressindex.h \
  spentindex.h \
  addrman.h \
  base58.h \
  bech32.h \
  bloom.h \
  blockencodings.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/airdropaddresses.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  pos/kernel.h \
  pos/miner.h \
  cuckoocache.h \
  fs.h \
  ghostnode/activeghostnode.h \
  ghostnode/darksend.h \
  ghostnode/darksend-relay.h \
  ghostnode/ghostnode.h \
  ghostnode/ghostnode-payments.h \
  ghostnode/ghostnode-sync.h \
  ghostnode/ghostnodeman.h \
  ghostnode/ghostnodeconfig.h \
  ghostnode/instantx.h \
  ghostnode/netfulfilledman.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  noui.h \
  policy/feerate.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  protocol.h \
  random.h \
  reverse_iterator.h \
  reverselock.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mining.h \
  rpc/protocol.h \
  rpc/safemode.h \
  rpc/server.h \
  rpc/register.h \
  rpc/util.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  ghost-address/commitmentkey.h \
  ghost-address/lz4.h \
  ghost-address/extkey.h \
  ghost-address/keystore.h \
  ghost-address/keyutil.h \
  ghost-address/mnemonic.h \
  ghost-address/stealth.h \
  ghost-address/types.h \
  ghost-address/xxhash.h \
  ghost-address/wordlists/chinese_simplified.h \
  ghost-address/wordlists/chinese_traditional.h \
  ghost-address/wordlists/english.h \
  ghost-address/wordlists/french.h \
  ghost-address/wordlists/japanese.h \
  ghost-address/wordlists/spanish.h \
  ghost-address/wordlists/italian.h \
  ghost-address/wordlists/korean.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  unilib/uninorms.h \
  unilib/utf8.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/init.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/walletutil.h \
  warnings.h \
  zerocoin/zerocoin.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  usbdevice/usbdevice.h \
  usbdevice/rpcusbdevice.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libnix_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between nixd and nix-qt
libnix_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libnix_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_server_a_SOURCES = \
  addrdb.cpp \
  addressindex.cpp \
  addrman.cpp \
  bloom.cpp \
  blockencodings.cpp \
  chain.cpp \
  checkpoints.cpp \
  consensus/tx_verify.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  ghostnode/rpcghostnode.cpp \
  ghostnode/netfulfilledman.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  policy/rbf.cpp \
  pos/kernel.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/mnemonic.cpp \
  rpc/safemode.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  zerocoin/zerocoin.cpp \
  $(NIX_CORE_H)

if ENABLE_ZMQ
libnix_zmq_a_CPPFLAGS = $(NIX_INCLUDES) $(ZMQ_CFLAGS)
libnix_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif

if ENABLE_USBDEVICE
libnix_usbdevice_a_CPPFLAGS = $(NIX_INCLUDES) $(AM_CPPFLAGS)
libnix_usbdevice_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_usbdevice_a_CFLAGS = -DHAVE_HIDAPI $(AM_CFLAGS)
libnix_usbdevice_a_SOURCES = \
  usbdevice/ledger/btchipApdu.h \
  usbdevice/ledger/ledgerLayer.h \
  usbdevice/ledger/ledgerLayer.c \
  usbdevice/ledger/dongleCommHidHidapi.h \
  usbdevice/ledger/dongleCommHidHidapi.c \
  usbdevice/usbdevice.cpp \
  usbdevice/debugdevice.h \
  usbdevice/debugdevice.cpp \
  usbdevice/ledgerdevice.h \
  usbdevice/ledgerdevice.cpp \
  usbdevice/rpcusbdevice.cpp
endif


# wallet: shared between nixd and nix-qt, but only linked
# when wallet enabled
libnix_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
libnix_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_wallet_a_SOURCES = \
  ghostnode/activeghostnode.cpp \
  ghostnode/darksend.cpp \
  ghostnode/darksend-relay.cpp \
  ghostnode/ghostnode.cpp \
  ghostnode/ghostnode-payments.cpp \
  ghostnode/ghostnode-sync.cpp \
  ghostnode/ghostnodeman.cpp \
  ghostnode/ghostnodeconfig.cpp \
  ghostnode/instantx.cpp \
  ghost-address/commitmentkey.cpp \
  pos/miner.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/init.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  $(NIX_CORE_H)

# crypto primitives library
crypto_libnix_crypto_a_CFLAGS = $(AM_CFLAGS) $(PIC_FLAGS)
crypto_libnix_crypto_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libnix_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libnix_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/Lyra2RE/Lyra2RE.c \
  crypto/Lyra2RE/Lyra2RE.h \
  crypto/Lyra2RE/Lyra2.c \
  crypto/Lyra2RE/Lyra2.h \
  crypto/Lyra2RE/Sponge.c \
  crypto/Lyra2RE/Sponge.h \
  crypto/Lyra2RE/blake.c \
  crypto/Lyra2RE/groestl.c \
  crypto/Lyra2RE/keccak.c \
  crypto/Lyra2RE/skein.c \
  crypto/Lyra2RE/cubehash.c \
  crypto/Lyra2RE/bmw.c \
  crypto/Lyra2RE/sph_blake.h \	
  crypto/Lyra2RE/sph_bmw.h \
  crypto/Lyra2RE/sph_cubehash.h \
  crypto/Lyra2RE/sph_groestl.h \
  crypto/Lyra2RE/sph_keccak.h \
  crypto/Lyra2RE/sph_skein.h \
  crypto/Lyra2RE/sph_types.h

if USE_ASM
crypto_libnix_crypto_a_SOURCES += crypto/sha256_sse4.cpp
endif

# consensus: shared between all executables that validate any consensus rules.
libnix_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
libnix_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  ghostnode/flat-database.h \
  ghostnode/spork.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/nixconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between nixd, and nix-qt and non-server tools
libnix_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
libnix_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_common_a_SOURCES = \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  ghostnode/spork.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  policy/feerate.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  unilib/uninorms.cpp \
  unilib/utf8.cpp \
  ghost-address/lz4.c \
  ghost-address/extkey.cpp \
  ghost-address/keystore.cpp \
  ghost-address/keyutil.cpp \
  ghost-address/mnemonic.cpp \
  ghost-address/stealth.cpp \
  ghost-address/xxhash.c \
  warnings.cpp \
  $(NIX_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libnix_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
libnix_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  libzerocoin/bignum.h \
  libzerocoin/Accumulator.h \
  libzerocoin/Accumulator.cpp \
  libzerocoin/AccumulatorProofOfKnowledge.h \
  libzerocoin/AccumulatorProofOfKnowledge.cpp \
  libzerocoin/Coin.h \
  libzerocoin/Coin.cpp \
  libzerocoin/CoinSpend.h \
  libzerocoin/CoinSpend.cpp \
  libzerocoin/Commitment.h \
  libzerocoin/Commitment.cpp \
  libzerocoin/ParallelTasks.h \
  libzerocoin/ParallelTasks.cpp \
  libzerocoin/ParamGeneration.h \
  libzerocoin/ParamGeneration.cpp \
  libzerocoin/Params.h \
  libzerocoin/Params.cpp \
  libzerocoin/SerialNumberSignatureOfKnowledge.h \
  libzerocoin/SerialNumberSignatureOfKnowledge.cpp \
  libzerocoin/SpendMetaData.h \
  libzerocoin/SpendMetaData.cpp \
  libzerocoin/Zerocoin.h \
  fs.cpp \
  random.cpp \
  rpc/protocol.cpp \
  rpc/util.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(NIX_CORE_H)


if GLIBC_BACK_COMPAT
libnix_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between nix-cli and nix-qt
libnix_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
libnix_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libnix_cli_a_SOURCES = \
  rpc/client.cpp \
  $(NIX_CORE_H)

nodist_libnix_util_a_SOURCES = $(srcdir)/obj/build.h
#

# nixd binary #
nixd_SOURCES = nixd.cpp
nixd_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
nixd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nixd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
nixd_SOURCES += nixd-res.rc
endif

nixd_LDADD = \
  $(LIBNIX_SERVER) \
  $(LIBNIX_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBNIX_UTIL) \
  $(LIBNIX_WALLET) \
  $(LIBNIX_ZMQ) \
  $(LIBNIX_CONSENSUS) \
  $(LIBNIX_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBNIX_USBDEVICE)

nixd_LDADD += $(TOR_LIBS) $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(USB_LIBS) -lz

# nix-cli binary #
nix_cli_SOURCES = nix-cli.cpp
nix_cli_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES) $(EVENT_CFLAGS)
nix_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nix_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
nix_cli_SOURCES += nix-cli-res.rc
endif

nix_cli_LDADD = \
  $(LIBNIX_CLI) \
  $(LIBUNIVALUE) \
  $(LIBNIX_UTIL) \
  $(LIBNIX_CRYPTO)

nix_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# nix-tx binary #
nix_tx_SOURCES = nix-tx.cpp
nix_tx_CPPFLAGS = $(AM_CPPFLAGS) $(NIX_INCLUDES)
nix_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
nix_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
nix_tx_SOURCES += nix-tx-res.rc
endif

nix_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBNIX_COMMON) \
  $(LIBNIX_UTIL) \
  $(LIBNIX_CONSENSUS) \
  $(LIBNIX_CRYPTO) \
  $(LIBSECP256K1)

nix_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# nixconsensus library #
if BUILD_NIX_LIBS
include_HEADERS = script/nixconsensus.h
libnixconsensus_la_SOURCES = $(crypto_libnix_crypto_a_SOURCES) $(libnix_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libnixconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libnixconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libnixconsensus_la_LIBADD = $(LIBSECP256K1)
libnixconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_NIX_INTERNAL
libnixconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h
CLEANFILES += tor.timestamp tor.timestamp.tmp

EXTRA_DIST = $(CTAES_DIST)


config/nix-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/nix-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/nix-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/nix-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-$(MAKE) -C tor clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
