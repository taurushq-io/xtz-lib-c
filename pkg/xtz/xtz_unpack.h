#pragma once
#include "xtz.h"
#include "bip/bip44.h"

xtz_request* xtz_unpack_reveal_request(const TpMessages__XTZRevealRequest *proto,
                                       uint8_t *seed, size_t seed_len,
                                       logger *log, 
                                       error *err);

xtz_request* xtz_unpack_delegations_request(const TpMessages__XTZDelegationsRequest *proto,
                                            uint8_t *seed, size_t seed_len,
                                            logger *log, 
                                            error *err);

xtz_request* xtz_unpack_transactions_request(const TpMessages__XTZTransactionsRequest *proto, 
                                             uint8_t* seed, size_t seed_len,
                                             logger *log, 
                                             error *err);

xtz_request* xtz_unpack_address_request(const TpMessages__XTZAddressRequest *proto,
                                        uint8_t hsm_key[SECP256R1_PRIVATE_KEY_SIZE],
                                        logger *log, 
                                        error *err);

xtz_request* xtz_unpack_reserve_request(TpMessages__XTZProofOfReserveRequest *proto, 
                                        const uint8_t* seed, size_t slen,
                                        logger *log, 
                                        error *err);

void xtz_free_unpacked(xtz_request* req);