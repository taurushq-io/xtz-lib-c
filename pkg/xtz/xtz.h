#pragma once

#include "utils/util.h"
#include "bip/slip10.h"


#define XTZ_ADDRESS_STR_LEN 36
#define XTZ_ADDRESS_STR_BUF_LEN XTZ_ADDRESS_STR_LEN+1 //36 + \0

#define XTZ_PUBKEY_HASH_LEN 20
#define XTZ_ADDRESS_BINARY_LEN XTZ_PUBKEY_HASH_PREFIX_LEN + XTZ_PUBKEY_HASH_LEN + 4

#define XTZ_BLOCK_HASH_LEN 32
#define XTZ_BLOCK_STR_LEN 51
#define XTZ_BLOCK_STR_BUF_LEN 52

#define XTZ_REVEAL_TAG 0x6b
#define XTZ_TRANSACTION_TAG 0x6c
#define XTZ_DELEGATE_TAG 0x6e
#define XTZ_ED25519_TAG 0x00

#define XTZ_OPERATION_HASH_LEN 32
#define XTZ_OPERATION_WATERMARK 0x03

#define XTZ_BLOCK_BINARY_LEN 38

#define XTZ_BLOCK_HASH_PREFIX "\x01\x34"
#define XTZ_BLOCK_HASH_PREFIX_LEN 2

#define XTZ_PUBKEY_HASH_PREFIX "\x06\xa1\x9f" // "\006\161\159"
#define XTZ_PUBKEY_HASH_PREFIX_LEN 3

#define XTZ_ED25519_PREFIX "\x06\xa1\x9f"
#define XTZ_ED25519_PREFIX_LEN 3
#define XTZ_SECP256K1_PREFIX "\x06\xa1\xa1"
#define XTZ_SECP256K1_PREFIX_LEN 3
#define XTZ_SECP256R1_PREFIX "\x06\xa1\xa4"
#define XTZ_SECP256R1_PREFIX_LEN 3
#define XTZ_CONTRACT_PREFIX "\x02\x5a\x79"
#define XTZ_CONTRACT_PREFIX_LEN 3


typedef enum {
    XTZ_ADDRESS_ED25519,
    XTZ_ADDRESS_SECP256K1,
    XTZ_ADDRESS_SECP256R1,
    XTZ_ADDRESS_CONTRACT,
    XTZ_ADDRESS_UNKNOWN,
} xtz_address_type;


typedef struct {
    xtz_address_type type;
    uint8_t hash[XTZ_PUBKEY_HASH_LEN];
} xtz_pubkey_hash;

typedef struct {
    char* path;
    uint8_t hsm_key[SECP256R1_PRIVATE_KEY_SIZE];
} xtz_address_request;

typedef struct {
    char *id;
    char *path;

    char branch[XTZ_BLOCK_HASH_LEN];
    nn fee;
    nn gas_limit;
    nn counter;

    //helpful
    slip10_extended_key key;
    uint8_t pubkey_hash[XTZ_PUBKEY_HASH_LEN];
} xtz_reveal_request;

typedef struct {
    char *id;
    char *path;

    char branch[XTZ_BLOCK_HASH_LEN];
    nn fee;
    nn gas_limit;
    nn counter;

    bool has_delegate;
    xtz_pubkey_hash delegate;

    //helpful
    slip10_extended_key key;
    uint8_t pubkey_hash[XTZ_PUBKEY_HASH_LEN];
    char *delegate_str;
} xtz_delegation;

typedef struct {
    xtz_delegation *dgs;
    size_t n_dgs;
} xtz_delegations_request;

#define XTZ_CONTRACT_ID_SIZE 22

typedef struct {
    char *id;
    char *path;

    uint8_t branch[XTZ_BLOCK_HASH_LEN];
    nn fee;
    nn counter;
    nn gas_limit;
    nn storage_limit;
    nn amount;

    uint8_t destination[XTZ_CONTRACT_ID_SIZE];

    uint8_t *parameters;
    size_t parameters_len;
    
    //helpful
    slip10_extended_key key;
    uint8_t pubkey_hash[XTZ_PUBKEY_HASH_LEN];
    char *destination_str;
} xtz_transaction;

typedef struct {
    xtz_transaction *txs;
    size_t n_txs;
} xtz_transactions_request;


typedef enum {
    XTZ_ADDRESS,
    XTZ_REVEAL,
    XTZ_TRANSACTIONS,
    XTZ_DELEGATIONS,
    XTZ_RESERVE,
} xtz_request_type;

typedef struct {
    slip10_extended_key key;
    char* path;
    char* chall;
    uint8_t hash[SHA256_DIGEST_SIZE];
} xtz_reserve_request;

typedef union {
    xtz_reserve_request reserve;
    xtz_address_request address;
    xtz_reveal_request reveal;
    xtz_transactions_request transactions;
    xtz_delegations_request delegations;
} _xtz_request;

typedef struct {
    xtz_request_type type;
    _xtz_request req;
} xtz_request;

bool xtz_get_cid_from_addr(uint8_t cid[XTZ_CONTRACT_ID_SIZE], const char address[XTZ_ADDRESS_STR_BUF_LEN], logger *log, error *err);
bool xtz_get_branch(uint8_t branch[XTZ_BLOCK_HASH_LEN], const char hash[XTZ_BLOCK_STR_BUF_LEN], logger *log, error *err);
bool xtz_get_pubkey_hash(xtz_pubkey_hash *pk, const char address[XTZ_ADDRESS_STR_BUF_LEN], logger *log, error *err);

array _xtz_transaction(const xtz_transaction *tx, logger *log, error *err);
array _xtz_delegation(const xtz_delegation *dg, logger *log, error *err);
array _xtz_reveal(const xtz_reveal_request *rv, logger *log, error *err);

array xtz_transactions(const xtz_transactions_request *tx, logger *log, error *err);
array xtz_delegations(const xtz_delegations_request *tx, logger *log, error *err);
array xtz_reveal(const xtz_reveal_request* req, logger *log, error *err);
array xtz_get_address(const xtz_address_request *req, const uint8_t *seed, size_t seed_len, logger *log, error *err);
bool xtz_get_rawaddr(char address[XTZ_ADDRESS_STR_BUF_LEN],
                     const char* path,
                     const uint8_t* seed,
                     size_t seed_len,
                     logger *log,
                     error *err);

bool xtz_get_addr_from_pubkey(char address[XTZ_ADDRESS_STR_BUF_LEN],
                              const uint8_t pubkey[ED25519_PUBLIC_KEY_SIZE],
                              logger *log,
                              error *err);