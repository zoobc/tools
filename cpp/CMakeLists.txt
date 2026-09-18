cmake_minimum_required(VERSION 3.16)
project(zoobc-tools LANGUAGES CXX)

# ZooBC command-line tools, C++ reference implementation.
#   libzbc      keys, addresses, hashing, transaction serialisation and signing, no node code
#   cmd/        one program per transaction type, the key and address generators, and zbc-cli
#
# Dependencies: libsodium, OpenSSL (TLS for https gateways, hashing), secp256k1 (Bitcoin and
# Ethereum style keys). Debian/Ubuntu: libsodium-dev libssl-dev libsecp256k1-dev.
# macOS (Homebrew): libsodium openssl@3 secp256k1, then -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3).

# `zbc-cli version` reports the tools release and the commit it was built from. In the node
# repository these come from its VERSION file; a public checkout has neither, so they come from
# here — keep the version in step with ts/package.json, py/pyproject.toml and rust/Cargo.toml.
set(ZBC_TOOLS_VERSION "0.1.1")
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
                    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                    OUTPUT_VARIABLE ZBC_GIT_COMMIT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()
if(NOT ZBC_GIT_COMMIT)
    set(ZBC_GIT_COMMIT "unknown")
endif()
add_compile_definitions(ZOOBC_VERSION="${ZBC_TOOLS_VERSION}" ZOOBC_GIT_COMMIT="${ZBC_GIT_COMMIT}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ZBC_STATIC: self-contained binaries. Third-party libraries and the C++ runtime are linked
# statically; libc stays dynamic (a fully static libc breaks DNS resolution). The result runs on
# any Linux of the same architecture with nothing installed.
option(ZBC_STATIC "Self-contained binaries (static third-party libraries, dynamic libc)" OFF)
if(ZBC_STATIC)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(sodium_USE_STATIC_LIBS TRUE)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_link_options(-static-libstdc++ -static-libgcc)
    endif()
    message(STATUS "ZBC_STATIC: self-contained binaries")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(sodium REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(SECP256K1_LIBRARY NAMES secp256k1
    PATHS /opt/homebrew/opt/secp256k1/lib /usr/local/opt/secp256k1/lib)
find_path(SECP256K1_INCLUDE_DIR NAMES secp256k1.h
    PATHS /opt/homebrew/opt/secp256k1/include /usr/local/opt/secp256k1/include)
if(NOT SECP256K1_LIBRARY OR NOT SECP256K1_INCLUDE_DIR)
    message(FATAL_ERROR "secp256k1 not found. Debian/Ubuntu: apt install libsecp256k1-dev. macOS: brew install secp256k1")
endif()

# ---------------------------------------------------------------------------- libzbc
file(GLOB_RECURSE ZBC_CORE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libzbc/src/*.cpp")
add_library(zbc STATIC ${ZBC_CORE_SOURCES})
target_include_directories(zbc
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/libzbc/include"
        ${SECP256K1_INCLUDE_DIR}
        ${sodium_INCLUDE_DIRS})
target_link_libraries(zbc PUBLIC sodium OpenSSL::Crypto ${SECP256K1_LIBRARY})
target_compile_features(zbc PUBLIC cxx_std_17)

# ---------------------------------------------------------------------------- tools
# Every tool is one source file under cmd/ compiled against libzbc. Transaction tools also use the
# header-only HTTP client and JSON library in third_party/ and TLS from OpenSSL.
set(ZBC_TOOL_TARGETS "")
function(zbc_tool NAME SOURCE)
    add_executable(${NAME} "cmd/${SOURCE}")
    target_include_directories(${NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/cmd"
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party")
    target_compile_definitions(${NAME} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(${NAME} PRIVATE zbc OpenSSL::SSL OpenSSL::Crypto)
    install(TARGETS ${NAME} RUNTIME DESTINATION bin)
    set(ZBC_TOOL_TARGETS ${ZBC_TOOL_TARGETS} ${NAME} PARENT_SCOPE)
endfunction()

# The combined command
zbc_tool(zbc-cli                  zoobc-cli.cpp)

# One program per transaction type
zbc_tool(zbc-send                 transfer.cpp)
zbc_tool(zbc-liquid-pay           liquid-payment.cpp)
zbc_tool(zbc-liquid-stop          liquid-payment-stop.cpp)
zbc_tool(zbc-token-issue          issue-token.cpp)
zbc_tool(zbc-token-transfer       token-transfer.cpp)
zbc_tool(zbc-token-mint           mint-token.cpp)
zbc_tool(zbc-token-burn           burn-token.cpp)
zbc_tool(zbc-token-finance        finance-token.cpp)
zbc_tool(zbc-swap-create          swap-create.cpp)
zbc_tool(zbc-swap-accept          swap-accept.cpp)
zbc_tool(zbc-swap-cancel          swap-cancel.cpp)
zbc_tool(zbc-market-create        market-create.cpp)
zbc_tool(zbc-order-place          order-place.cpp)
zbc_tool(zbc-order-cancel         order-cancel.cpp)
zbc_tool(zbc-app-create           app-create.cpp)
zbc_tool(zbc-app-join             app-join.cpp)
zbc_tool(zbc-app-move             app-move.cpp)
zbc_tool(zbc-app-resign           app-resign.cpp)
zbc_tool(zbc-app-claim            app-claim.cpp)
zbc_tool(zbc-app-settle           app-settle.cpp)
zbc_tool(zbc-storage-prepay       add-prepaid-storage.cpp)
zbc_tool(zbc-dfs-create-file      dfs-create-file.cpp)
zbc_tool(zbc-escrow-approve       approve-escrow.cpp)
zbc_tool(zbc-escrow-request       escrow-request.cpp)
zbc_tool(zbc-event-attest         attest-event.cpp)
zbc_tool(zbc-trigger-create       create-trigger.cpp)
zbc_tool(zbc-trigger-cancel       cancel-trigger.cpp)
zbc_tool(zbc-fund-longevity       fund-longevity.cpp)
zbc_tool(zbc-cancel-longevity     cancel-longevity.cpp)
zbc_tool(zbc-dataset-setup        setup-dataset.cpp)
zbc_tool(zbc-dataset-remove       remove-dataset.cpp)
zbc_tool(zbc-fee-vote-commit      fee-vote-commit.cpp)
zbc_tool(zbc-fee-vote-reveal      fee-vote-reveal.cpp)
zbc_tool(zbc-multisig             multisig.cpp)
zbc_tool(zbc-governance-vote      governance-vote.cpp)
zbc_tool(zbc-node-register        register-node.cpp)
zbc_tool(zbc-node-update          update-node.cpp)
zbc_tool(zbc-node-remove          remove-node.cpp)
zbc_tool(zbc-node-claim           claim-node.cpp)
zbc_tool(zbc-gateway-register     gateway-register.cpp)
zbc_tool(zbc-gateway-unregister   gateway-unregister.cpp)
zbc_tool(zbc-archival-register    archival-register.cpp)
zbc_tool(zbc-archival-unregister  archival-unregister.cpp)
zbc_tool(zbc-relay-register       relay-register.cpp)
zbc_tool(zbc-relay-unregister     relay-unregister.cpp)

# Keys and addresses (no network)
zbc_tool(zbc-key-gen              keygen.cpp)
zbc_tool(zbc-account-gen          account-gen.cpp)
zbc_tool(zbc-node-gen             bcn-address-gen.cpp)
zbc_tool(zbc-wallet-gen           wallet-gen.cpp)
zbc_tool(zbc-account-from-key     zbc-from-privkey.cpp)
zbc_tool(zbc-node-from-key        znk-from-privkey.cpp)
zbc_tool(zbc-message-decrypt      decrypt-message.cpp)
foreach(pair "eth;ethereum" "btc;bitcoin" "solana;solana" "polkadot;polkadot")
    list(GET pair 0 short)
    list(GET pair 1 chain)
    zbc_tool(zbc-account-${short} account-gen.cpp)
    target_compile_definitions(zbc-account-${short} PRIVATE ZBC_ACCOUNT_FIXED_CHAIN="${chain}")
endforeach()

# ---------------------------------------------------------------------------- tests
# Offline checks only: the tools' own list, key derivation, message signing and verification,
# usage and unreachable-node exit codes. Nothing here talks to a network.
enable_testing()
add_test(NAME smoke
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh" "$<TARGET_FILE_DIR:zbc-cli>")
