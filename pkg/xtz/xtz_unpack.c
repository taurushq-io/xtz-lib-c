#include "xtz_unpack.h"


static bool _xtz_check_path(char* path, error *err) {
    ERR_CHECK_RETURN
    chknull(path)
    bool status = false;

    ERR_NEW_CND(path, E_VALIDATION, exit, "given path is null")
    ERR_NEW_CND(is_bip44_prefix(BIP44_XTZ_PREFIX, path), E_VALIDATION, exit, "invalid path for xtz (expected prefix %s)", BIP44_XTZ_PREFIX)
    int level = slip10_get_level(path);
    ERR_NEW_CND(level == BIP44_ADDRESS_LEVEL, E_VALIDATION, exit, "invalid level for path, expected %d got %d", BIP44_ADDRESS_LEVEL, level)

    status = true;
exit:
    return status;
} 

xtz_request* xtz_unpack_address_request(const TpMessages__XTZAddressRequest *proto, 
                                        uint8_t hsm_key[SECP256R1_PRIVATE_KEY_SIZE],
                                        logger *log,
                                        error *err) {
    ERR_CHECK_RETURN
    chknull(proto)
    
    // free'd in failure or in xtz_pipeline by calling xtz_free_unpacked
    xtz_request *req = calloc(1, sizeof(xtz_request));
    ERR_NEW_CND(req, E_ALLOC, fail, "failed to allocate memory for internal request");
    req->type = XTZ_ADDRESS;
    xtz_address_request *addr = &req->req.address;
    memcpy(addr->hsm_key, hsm_key, SECP256R1_PRIVATE_KEY_SIZE);

    ERR_WRAP_CND(_xtz_check_path(proto->path, err), fail, "invalid address path")
    addr->path = proto->path;
    return req;
fail:
    xtz_free_unpacked(req);
    return NULL;
}

xtz_request* xtz_unpack_transactions_request(const TpMessages__XTZTransactionsRequest *proto,
                                             uint8_t* seed, size_t seed_len,
                                             logger *log,
                                             error *err) {
    ERR_CHECK_RETURN
    chknull(proto)

    // free'd in failure or in xtz_pipeline by calling xtz_free_unpacked
    xtz_request *req = calloc(1, sizeof(xtz_request));
    ERR_NEW_CND(req, E_ALLOC, fail, "failed to allocate memory for internal request");
    req->type = XTZ_TRANSACTIONS;
    xtz_transactions_request *txs = &req->req.transactions;

    txs->txs = calloc(proto->n_transactions, sizeof(xtz_transaction));
    ERR_NEW_CND(txs->txs, E_ALLOC, fail, "failed to allocate memory for %d txs", proto->n_transactions)
    txs->n_txs = proto->n_transactions;
    for(int i=0;i<proto->n_transactions;i++) {
        TpMessages__XTZTransaction *tx = proto->transactions[i];

        ERR_NEW_CND(tx->id, E_VALIDATION, fail, "transaction %d has null id", i)
        txs->txs[i].id = tx->id;
        ERR_WRAP_CND(xtz_get_branch((uint8_t*) txs->txs[i].branch, tx->branch, log, err), fail, "failed to extract branch hash")
        ERR_WRAP_CND(_xtz_check_path(tx->from, err), fail, "invalid source for transaction %d", i)
        txs->txs[i].path = tx->from;
        
        uint8_t fee[8];
        int64_to_buf(tx->fee, fee)
        nn_init_from_buf(&txs->txs[i].fee, fee, 8);
        nn_init_from_buf(&txs->txs[i].counter, tx->counter.data, tx->counter.len);
        nn_init_from_buf(&txs->txs[i].gas_limit, tx->gaslimit.data, tx->gaslimit.len);
        nn_init_from_buf(&txs->txs[i].storage_limit, tx->storagelimit.data, tx->storagelimit.len);
        
        uint8_t amount[8];
        int64_to_buf(tx->amount, amount)
        nn_init_from_buf(&txs->txs[i].amount, amount, 8);
        
        ERR_NEW_CND(tx->to, E_VALIDATION, fail, "transaction %d has null destination", i)
        txs->txs[i].destination_str = tx->to;
        ERR_WRAP_CND(xtz_get_cid_from_addr(txs->txs[i].destination, tx->to, log, err), fail, "failed to extract hash from destination")

        txs->txs[i].parameters = tx->parameters.data;
        txs->txs[i].parameters_len = tx->parameters.len;

        ERR_WRAP_CND(slip10_derive(&txs->txs[i].key, SLIP10_CURVE_ED25519, tx->from, seed, seed_len, 
                log, err), fail, "failed to derive key");
        ERR_WRAP_CND(crypto_operations.blake2b(txs->txs[i].pubkey_hash, XTZ_PUBKEY_HASH_LEN, txs->txs[i].key.public_key, 
                txs->txs[i].key.pubkey_len, NULL, 0, log, err), fail, "failed to get pubkey hash")
    }
    return req;
fail:
    xtz_free_unpacked(req);
    return NULL;
}

xtz_request* xtz_unpack_delegations_request(const TpMessages__XTZDelegationsRequest *proto,
                                            uint8_t* seed, size_t seed_len,
                                            logger *log,
                                            error *err) {
    ERR_CHECK_RETURN
    chknull(proto)

    // free'd in failure or in xtz_pipeline by calling xtz_free_unpacked
    xtz_request *req = calloc(1, sizeof(xtz_request));
    ERR_NEW_CND(req, E_ALLOC, fail, "failed to allocate memory for internal request");
    req->type = XTZ_DELEGATIONS;
    xtz_delegations_request *dgs = &req->req.delegations;

    dgs->dgs = calloc(proto->n_delegations, sizeof(xtz_delegation));
    ERR_NEW_CND(dgs->dgs, E_ALLOC, fail, "failed to allocate memory for %d dgs", proto->n_delegations)
    dgs->n_dgs = proto->n_delegations;
    for(int i=0;i<proto->n_delegations;i++) {
        TpMessages__XTZDelegation *dg = proto->delegations[i];

        ERR_NEW_CND(dg->id, E_VALIDATION, fail, "delegation %d has null id", i)
        dgs->dgs[i].id = dg->id;
        ERR_WRAP_CND(xtz_get_branch((uint8_t*) dgs->dgs[i].branch, dg->branch, log, err), fail, "failed to extract branch hash")
        ERR_WRAP_CND(_xtz_check_path(dg->from, err), fail, "invalid source for delegation %d", i)
        dgs->dgs[i].path = dg->from;
        
        uint8_t fee[8];
        int64_to_buf(dg->fee, fee)
        nn_init_from_buf(&dgs->dgs[i].fee, fee, 8);
        nn_init_from_buf(&dgs->dgs[i].counter, dg->counter.data, dg->counter.len);
        nn_init_from_buf(&dgs->dgs[i].gas_limit, dg->gaslimit.data, dg->gaslimit.len);
        
        if(!dg->delegate) {
            dgs->dgs[i].has_delegate = false;
        } else {
            dgs->dgs[i].has_delegate = true;
            dgs->dgs[i].delegate_str = dg->delegate;
            ERR_WRAP_CND(xtz_get_pubkey_hash(&dgs->dgs[i].delegate, dg->delegate, log, err), fail, "failed to extract hash from delegate")
        }
        ERR_WRAP_CND(slip10_derive(&dgs->dgs[i].key, SLIP10_CURVE_ED25519, dg->from, seed, seed_len, 
                log, err), fail, "failed to derive key");
        ERR_WRAP_CND(crypto_operations.blake2b(dgs->dgs[i].pubkey_hash, XTZ_PUBKEY_HASH_LEN, dgs->dgs[i].key.public_key, 
                dgs->dgs[i].key.pubkey_len, NULL, 0, log, err), fail, "failed to get pubkey hash")
    }
    return req;
fail:
    xtz_free_unpacked(req);
    return NULL;
}

xtz_request* xtz_unpack_reveal_request(const TpMessages__XTZRevealRequest *proto,
                                       uint8_t* seed, size_t seed_len,
                                       logger *log,
                                       error *err) {
    ERR_CHECK_RETURN
    chknull(proto)

    // free'd in failure or in xtz_pipeline by calling xtz_free_unpacked
    xtz_request *req = calloc(1, sizeof(xtz_request));
    ERR_NEW_CND(req, E_ALLOC, fail, "failed to allocate memory for internal request");
    req->type = XTZ_REVEAL;
    xtz_reveal_request *rv = &req->req.reveal;

    ERR_NEW_CND(proto->id, E_VALIDATION, fail, "reveal has null id")
    rv->id = proto->id;
    ERR_WRAP_CND(xtz_get_branch((uint8_t*) rv->branch, proto->branch, log, err), fail, "failed to extract branch hash")
    ERR_WRAP_CND(_xtz_check_path(proto->from, err), fail, "invalid source for reveal")
    rv->path = proto->from;
        
    uint8_t fee[8];
    int64_to_buf(proto->fee, fee)
    nn_init_from_buf(&rv->fee, fee, 8);
    nn_init_from_buf(&rv->counter, proto->counter.data, proto->counter.len);
    nn_init_from_buf(&rv->gas_limit, proto->gaslimit.data, proto->gaslimit.len);
    ERR_WRAP_CND(slip10_derive(&rv->key, SLIP10_CURVE_ED25519, proto->from, seed, seed_len, 
            log, err), fail, "failed to derive key");
    ERR_WRAP_CND(crypto_operations.blake2b(rv->pubkey_hash, XTZ_PUBKEY_HASH_LEN, rv->key.public_key, 
            rv->key.pubkey_len, NULL, 0, log, err), fail, "failed to get pubkey hash")
    return req;
fail:
    xtz_free_unpacked(req);
    return NULL;
}

xtz_request *xtz_unpack_reserve_request(TpMessages__XTZProofOfReserveRequest *proto, 
                                         const uint8_t* seed, size_t slen,
                                         logger *log,
                                         error *err) {
    ERR_CHECK_RETURN
    chknull(proto)
    chknull(seed)
    xtz_request *req = calloc(1, sizeof(xtz_request));
    ERR_NEW_CND(req, E_ALLOC, fail, "failed to allocate memory for internal request");
    req->type = XTZ_RESERVE;
    xtz_reserve_request *reserve = &req->req.reserve;

    // challenge
    ERR_NEW_CND(proto->challenge, E_VALIDATION, fail, "null challenge")
    size_t clen = strlen(proto->challenge);
    ERR_NEW_CND(clen > 0, E_VALIDATION, fail, "empty challenge")
    ERR_NEW_CND(clen < 65, E_VALIDATION, fail, "challenge too large, max 64 characters")
    for(size_t i = 0; i<clen; i++) {
        if(!(
            isalnum(proto->challenge[i]) ||
            proto->challenge[i] == ' ' ||
            proto->challenge[i] == '-' ||
            proto->challenge[i] == '_'
        )) {
            ERR_NEW_CND(false, E_VALIDATION, fail, "invalid character %c at index %ld", proto->challenge[i], i)
        }
    }
    reserve->chall = proto->challenge;
    ERR_WRAP_CND(crypto_operations.sha256(reserve->hash, (uint8_t*) reserve->chall, clen, 
            log, err), fail, "failed to hash challenge")
        
    // path
    ERR_NEW_CND(proto->path, E_VALIDATION, fail, "null path")
    ERR_WRAP_CND(_xtz_check_path(proto->path, err), fail, "failed to check path")
    reserve->path = proto->path;
    ERR_WRAP_CND(slip10_derive(&reserve->key, SLIP10_CURVE_ED25519, proto->path, seed, slen, log, err), 
            fail, "failed to derive key from path")
    return req;
fail:
    xtz_free_unpacked(req);
    return NULL;
}

void xtz_free_unpacked(xtz_request *req) {
    if(!req) return;
    switch(req->type) {
    case XTZ_ADDRESS:
    case XTZ_REVEAL:
    case XTZ_RESERVE:
    break;
    case XTZ_TRANSACTIONS:
        free(req->req.transactions.txs);
    break;
    case XTZ_DELEGATIONS:
        free(req->req.delegations.dgs);
    break;
    }
    free(req);
}