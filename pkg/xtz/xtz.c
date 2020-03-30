#include "xtz.h"
#include "xtz_serialization.h"
#include "bip/slip10.h"
#include "base58.h"

static xtz_address_type _xtz_get_address_type(const char addr[XTZ_ADDRESS_BINARY_LEN]) {
    if(strncmp(addr, XTZ_ED25519_PREFIX, XTZ_ED25519_PREFIX_LEN) == 0) return XTZ_ADDRESS_ED25519;
    if(strncmp(addr, XTZ_SECP256K1_PREFIX, XTZ_SECP256K1_PREFIX_LEN) == 0) return XTZ_ADDRESS_SECP256K1;
    if(strncmp(addr, XTZ_SECP256R1_PREFIX, XTZ_SECP256R1_PREFIX_LEN) == 0) return XTZ_ADDRESS_SECP256R1;
    if(strncmp(addr, XTZ_CONTRACT_PREFIX, XTZ_CONTRACT_PREFIX_LEN) == 0) return XTZ_ADDRESS_CONTRACT;
    return XTZ_ADDRESS_UNKNOWN;
}

bool xtz_get_branch(uint8_t branch[XTZ_BLOCK_HASH_LEN], const char hash[XTZ_BLOCK_STR_BUF_LEN], logger *log, error *err) {
    ERR_CHECK_RETURN
    bool status = false;

    uint8_t block[XTZ_BLOCK_BINARY_LEN];
    size_t binsz = XTZ_BLOCK_BINARY_LEN;
    ERR_NEW_CND(b58tobin(block, &binsz, hash, strlen(hash)), E_VALIDATION, exit, "failed to decode b58 address")


    ERR_NEW_CND(bufncmp(block, (uint8_t*) XTZ_BLOCK_HASH_PREFIX, XTZ_BLOCK_HASH_PREFIX_LEN), E_VALIDATION, exit, "branch doesn't match prefix")
    
    uint8_t tmp[SHA256_DIGEST_SIZE];
    ERR_WRAP_CND(crypto_operations.sha256(tmp, block, XTZ_BLOCK_HASH_PREFIX_LEN+XTZ_BLOCK_HASH_LEN, 
            log, err), exit, "failed to sha256")
    uint8_t checksum[SHA256_DIGEST_SIZE];
    ERR_WRAP_CND(crypto_operations.sha256(checksum, tmp, SHA256_DIGEST_SIZE, log, err), exit, "failed to sha256")

    ERR_NEW_CND(bufncmp(block+XTZ_BLOCK_HASH_PREFIX_LEN+XTZ_BLOCK_HASH_LEN, checksum, 4), 
            E_VALIDATION, exit, "invalid checksum")

    memcpy(branch, block+XTZ_BLOCK_HASH_PREFIX_LEN, XTZ_BLOCK_HASH_LEN);
    status = true;
exit:
    return status;
}

bool xtz_get_pubkey_hash(xtz_pubkey_hash *pk, const char address[XTZ_ADDRESS_STR_BUF_LEN], logger *log, error *err) {
    ERR_CHECK_RETURN
    chknull(pk)
    bool status = false;
    
    uint8_t addr_bin[XTZ_ADDRESS_BINARY_LEN];
    size_t binsz = XTZ_ADDRESS_BINARY_LEN;
    ERR_NEW_CND(b58tobin(addr_bin, &binsz, address, strlen(address)), E_VALIDATION, exit, "failed to decode b58 address")

    uint8_t tmp[SHA256_DIGEST_SIZE];
    ERR_WRAP_CND(crypto_operations.sha256(tmp, addr_bin, XTZ_PUBKEY_HASH_PREFIX_LEN+XTZ_PUBKEY_HASH_LEN, 
                    log, err), exit, "failed to sha256")
    uint8_t checksum[SHA256_DIGEST_SIZE];
    ERR_WRAP_CND(crypto_operations.sha256(checksum, tmp, SHA256_DIGEST_SIZE, log, err), exit, "failed to sha256")

    xtz_address_type type = _xtz_get_address_type((char*) addr_bin);
    switch(type) {
    case XTZ_ADDRESS_ED25519:
    case XTZ_ADDRESS_SECP256K1:
    case XTZ_ADDRESS_SECP256R1:
    case XTZ_ADDRESS_CONTRACT:
        pk->type = type;
        memcpy(pk->hash, addr_bin+XTZ_PUBKEY_HASH_PREFIX_LEN, XTZ_PUBKEY_HASH_LEN);
    break;
    default:
        ERR_NEW_CND(false, E_VALIDATION, exit, "address does not match any known prefix")
    }

    ERR_NEW_CND(bufncmp(addr_bin+XTZ_PUBKEY_HASH_PREFIX_LEN+XTZ_PUBKEY_HASH_LEN, checksum, 4), 
        E_VALIDATION, exit, "invalid checksum")

    status = true;
exit:
    return status;
}

bool xtz_get_cid_from_addr(uint8_t cid[XTZ_CONTRACT_ID_SIZE],
                           const char address[XTZ_ADDRESS_STR_BUF_LEN],
                           logger *log,
                           error *err) {
    ERR_CHECK_RETURN
    bool status = false;

    xtz_pubkey_hash hash;
    ERR_WRAP_CND(xtz_get_pubkey_hash(&hash, address, log, err), exit, "failed to get pubkey hash")
    size_t offset = 0;
    switch(hash.type) {
    case XTZ_ADDRESS_ED25519:
        cid[0] = 0;
        cid[1] = 0;
        offset = 2;
    break;
    case XTZ_ADDRESS_SECP256K1:
        cid[0] = 0;
        cid[1] = 1;
        offset = 2;
    break;
    case XTZ_ADDRESS_SECP256R1:
        cid[0] = 0;
        cid[1] = 2;
        offset = 2;
    break;
    case XTZ_ADDRESS_CONTRACT:
        cid[0] = 1;
        cid[XTZ_CONTRACT_ID_SIZE-1] = 0;
        offset = 1;
    break;
    default: break;
    }
    memcpy(cid+offset, hash.hash, XTZ_PUBKEY_HASH_LEN);
    status = true;
exit:
    return status;
}

bool xtz_get_addr_from_pubkey(char address[XTZ_ADDRESS_STR_BUF_LEN],
                              const uint8_t pubkey[ED25519_PUBLIC_KEY_SIZE],
                              logger *log,
                              error *err) {
    ERR_CHECK_RETURN
    bool status = false;
    uint8_t pkhash[XTZ_PUBKEY_HASH_LEN];
    ERR_WRAP_CND(crypto_operations.blake2b(pkhash, XTZ_PUBKEY_HASH_LEN, pubkey, ED25519_PUBLIC_KEY_SIZE, NULL, 0, 
            log, err), exit, "failed to hash public key")

    uint8_t buf[XTZ_ADDRESS_BINARY_LEN];
    memcpy(buf, XTZ_PUBKEY_HASH_PREFIX, XTZ_PUBKEY_HASH_PREFIX_LEN);
    memcpy(buf+XTZ_PUBKEY_HASH_PREFIX_LEN, pkhash, XTZ_PUBKEY_HASH_LEN);

    uint8_t tmp[SHA256_DIGEST_SIZE];
    ERR_WRAP_CND(crypto_operations.sha256(tmp, buf, XTZ_PUBKEY_HASH_PREFIX_LEN+XTZ_PUBKEY_HASH_LEN, 
            log, err), exit, "failed to sha256")
    uint8_t digest[SHA256_DIGEST_SIZE];
    ERR_WRAP_CND(crypto_operations.sha256(digest, tmp, SHA256_DIGEST_SIZE, log, err), exit, "failed to sha256")
    memcpy(buf+XTZ_PUBKEY_HASH_PREFIX_LEN+XTZ_PUBKEY_HASH_LEN, digest, 4);

    size_t sz = XTZ_ADDRESS_STR_BUF_LEN;
    ERR_NEW_CND(b58enc(address, &sz, buf, XTZ_ADDRESS_BINARY_LEN), E_GENERAL, exit, "failed to encode address in b58")

    status = true;
exit:
    return status;
}

bool xtz_get_rawaddr(char address[XTZ_ADDRESS_STR_BUF_LEN],
                     const char* path,
                     const uint8_t* seed,
                     size_t seed_len,
                     logger *log,
                     error *err) {
    ERR_CHECK_RETURN
    chknull(path)
    chknull(seed)
    bool status = false;

    slip10_extended_key k;
    ERR_WRAP_CND(slip10_derive(&k, SLIP10_CURVE_ED25519, path, seed, seed_len, log, err), exit, "failed to get xtz keypair")
    ERR_WRAP_CND(xtz_get_addr_from_pubkey(address, k.public_key, log, err), exit, "failed to get address from pubkey")
    status = true;    
exit:
    return status;
}


array xtz_operation(uint8_t branch[XTZ_BLOCK_HASH_LEN],
                    uint8_t *contents,
                    size_t clen,
                    slip10_extended_key k,
                    logger *log,
                    error *err) {
    ERR_CHECK_RETURN
    chknull(contents)

    array ret = NULL;
    uint8_t *buf = NULL;
    size_t alloc_len = 0;
    safe_add(alloc_len, clen, 1, exit);
    buf = calloc(alloc_len, sizeof(uint8_t));
    ERR_NEW_CND(buf, E_ALLOC, exit, "failed to allocate memory for buf")

    uint8_t hash[XTZ_OPERATION_HASH_LEN];
    buf[0] = XTZ_OPERATION_WATERMARK;
    memcpy(buf+1, contents, clen);
    ERR_WRAP_CND(crypto_operations.blake2b(hash, XTZ_OPERATION_HASH_LEN, buf, clen+1, NULL, 0, 
            log, err), exit, "failed to hash watermarked content")

    uint8_t sig[ED25519_SIGNATURE_SIZE];
    ERR_WRAP_CND(crypto_operations.ed25519_sign(sig, k.private_key, hash, XTZ_OPERATION_HASH_LEN, 
            log, err), exit, "failed to sign with ed25519")

    ret = array_new(clen+ED25519_SIGNATURE_SIZE, sizeof(uint8_t));
    ERR_NEW_CND(ret, E_ALLOC, exit, "failed to allocate memory for return array")

    memcpy(ret->data, contents, clen);
    memcpy(ret->data+clen, sig, ED25519_SIGNATURE_SIZE);

exit:
    free(buf);
    return ret;
}

array _xtz_reveal(const xtz_reveal_request *rev, logger *log, error *err) {
    ERR_CHECK_RETURN
    chknull(rev)
    array ret = NULL;
    uint8_t *contents = NULL;

    size_t sz = xtz_sizeof_serialize_reveal(rev);

    contents = malloc(sz);
    ERR_NEW_CND(contents, E_ALLOC, exit, "failed to allocate %d bytes for reveal contents", sz)
    xtz_serialize_reveal(contents, rev);

    ret = xtz_operation((uint8_t*) rev->branch, contents, sz, rev->key, log, err);
exit:
    free(contents);
    return ret;
}

array _xtz_delegation(const xtz_delegation *req, logger *log, error *err) {
    ERR_CHECK_RETURN
    chknull(req)
    array ret = NULL;
    uint8_t *contents = NULL;

    size_t sz = xtz_sizeof_serialize_delegate(req);

    contents = malloc(sz);
    ERR_NEW_CND(contents, E_ALLOC, exit, "failed to allocate %d bytes for delegate contents", sz)
    xtz_serialize_delegate(contents, req);

    ret = xtz_operation((uint8_t*) req->branch, contents, sz, req->key, log, err);
exit:
    free(contents);
    return ret;
}

array _xtz_transaction(const xtz_transaction *tx, logger *log, error *err) {
    ERR_CHECK_RETURN
    chknull(tx)
    array ret = NULL;
    uint8_t *contents = NULL;

    size_t sz = xtz_sizeof_serialize_transaction(tx);

    contents = malloc(sz);
    ERR_NEW_CND(contents, E_ALLOC, exit, "failed to allocate %d bytes for transactions contents", sz)
    xtz_serialize_transaction(contents, tx);

    ret = xtz_operation((uint8_t*) tx->branch, contents, sz, tx->key, log, err);
exit:
    free(contents);
    return ret;
}

array xtz_get_address (const xtz_address_request* req,
                       const uint8_t *seed,
                       size_t seed_len,
                       logger *log,
                       error *err) {
    ERR_CHECK_RETURN   
    array ret = NULL;

    slip10_extended_key keypair;
    ERR_WRAP_CND(slip10_derive(&keypair, SLIP10_CURVE_ED25519, req->path, seed, seed_len, log, err), exit, "failed to derive bip32 key")

    char address[64];
    ERR_WRAP_CND(xtz_get_addr_from_pubkey(address, keypair.public_key, log, err), exit, "failed to get address from keypair")

    TpMessages__AddressResponse response;
    tp_messages__address_response__init(&response);
    response.address = address;
    uint8_t sig[SECP256R1_SIG_SIZE];
    response.signature.data = sig;
    response.signature.len = SECP256R1_SIG_SIZE;
    ERR_WRAP_CND(crypto_operations.secp256r1_sha256_sign(response.signature.data, req->hsm_key, 
            (uint8_t*) address, strlen(address), log, err), exit, "failed to sign address")

    size_t psize = tp_messages__address_response__get_packed_size(&response);
    ret = array_new(psize, sizeof(uint8_t));
    ERR_NEW_CND(ret, E_ALLOC, exit, "failed to allocate memory for return array")
    tp_messages__address_response__pack(&response, ret->data);
exit:
    return ret;
}

array xtz_reveal(const xtz_reveal_request* req, logger *log, error *err) {
    ERR_CHECK_RETURN   
    array ret = NULL;
    array res = NULL;

    TpMessages__TransactionsResponse response;
    tp_messages__transactions_response__init(&response);
    TpMessages__TransactionsResponse__Transaction tx;
    tp_messages__transactions_response__transaction__init(&tx);
    TpMessages__TransactionsResponse__Transaction *txp = &tx;

    res = _xtz_reveal(req, log, err);
    ERR_WRAP_CND(res, exit, "failed to process reveal request")

    response.n_transactions = 1;

    tx.id = req->id;

    size_t alloc_len = 0;
    safe_mul(alloc_len, res->len, 2, exit)
    safe_add(alloc_len, alloc_len, 1, exit)
    char *tx_str = malloc(alloc_len);
    ERR_NEW_CND(tx_str, E_ALLOC, exit, "failed to allocate memory for tx as string (len %d)", res->len*2+1)
    string_from_hex(tx_str, res->len*2+1, res->data, res->len);
    tx.transaction = tx_str;
    response.transactions = &txp;

    size_t psize = tp_messages__transactions_response__get_packed_size(&response);
    ret = array_new(psize, sizeof(uint8_t));
    ERR_NEW_CND(ret, E_ALLOC, exit, "failed to allocate memory for return array")
    tp_messages__transactions_response__pack(&response, ret->data);
exit:
    free(tx.transaction);
    array_free(&res);
    return ret;
}

array xtz_transactions(const xtz_transactions_request *req, logger *log, error *err) {
    ERR_CHECK_RETURN
    chknull(req)
    // returned
    array ret = NULL;

    // free'd in exit
    array tmp = NULL;
    TpMessages__TransactionsResponse response;
    tp_messages__transactions_response__init(&response);

    // free'd in exit
    response.transactions = calloc(req->n_txs, sizeof(ProtobufCBinaryData));
    ERR_NEW_CND(response.transactions, E_ALLOC, exit, "failed to allocate memory for response transactions")
    response.n_transactions = req->n_txs; // specify after for free
    
    for(int i=0;i<req->n_txs;i++) {
        //free'd in exit
        response.transactions[i] = calloc(1, sizeof(TpMessages__TransactionsResponse__Transaction));
        ERR_NEW_CND(response.transactions[i], E_ALLOC, exit, "failed to allocate memory for transaction %d in response", i);
        tp_messages__transactions_response__transaction__init(response.transactions[i]);
        //free without worrying about freeing ""
        response.transactions[i]->transaction = NULL; 
    }

    for(int i=0;i<req->n_txs;i++) {
        // free'd before reassigning and in exit
        array_free(&tmp);
        tmp = _xtz_transaction(&req->txs[i], log, err);
        ERR_WRAP_CND(tmp, exit, "failed to create transaction %d", i)
        
        // free'd when freeing response.transactions[i].transaction
        size_t alloc_len = 0;
        safe_mul(alloc_len, tmp->len, 2, exit)
        safe_add(alloc_len, alloc_len, 1, exit)
        char* tx_str = malloc(alloc_len);
        ERR_NEW_CND(tx_str, E_ALLOC, exit, "failed to allocate memory for tx as string (len %d)", alloc_len)
        string_from_hex(tx_str, alloc_len, tmp->data, tmp->len);
        
        response.transactions[i]->transaction = tx_str;
        response.transactions[i]->id = req->txs[i].id;
    }

    size_t psize = tp_messages__transactions_response__get_packed_size(&response);
    ret=array_new(psize, sizeof(uint8_t));
    ERR_NEW_CND(ret, E_ALLOC, exit, "failed to allocate %d bytes for packed transactions response", psize)
    
    tp_messages__transactions_response__pack(&response, ret->data);

exit:
    for(int i=0;i<response.n_transactions;i++) {
        if(response.transactions[i]) {
            free(response.transactions[i]->transaction);
        }
        free(response.transactions[i]);
    }
    free(response.transactions);
    array_free(&tmp);
    return ret;
}

array xtz_delegations(const xtz_delegations_request *req, logger *log, error *err) {
    ERR_CHECK_RETURN
    chknull(req)
    // returned
    array ret = NULL;

    // free'd in exit
    array tmp = NULL;
    TpMessages__TransactionsResponse response;
    tp_messages__transactions_response__init(&response);

    // free'd in exit
    response.transactions = calloc(req->n_dgs, sizeof(ProtobufCBinaryData));
    ERR_NEW_CND(response.transactions, E_ALLOC, exit, "failed to allocate memory for response transactions")
    response.n_transactions = req->n_dgs; // specify after for free
    
    for(int i=0;i<req->n_dgs;i++) {
        //free'd in exit
        response.transactions[i] = calloc(1, sizeof(TpMessages__TransactionsResponse__Transaction));
        ERR_NEW_CND(response.transactions[i], E_ALLOC, exit, "failed to allocate memory for delegation %d in response", i);
        tp_messages__transactions_response__transaction__init(response.transactions[i]);
        //free without worrying about freeing ""
        response.transactions[i]->transaction = NULL; 
    }

    for(int i=0;i<req->n_dgs;i++) {
        // free'd before reassigning and in exit
        array_free(&tmp);
        tmp = _xtz_delegation(&req->dgs[i], log, err);
        ERR_WRAP_CND(tmp, exit, "failed to create delegation %d", i)
        
        // free'd when freeing response.transactions[i].transaction
        size_t alloc_len = 0;
        safe_mul(alloc_len, tmp->len, 2, exit)
        safe_add(alloc_len, alloc_len, 1, exit)
        char* tx_str = malloc(alloc_len);
        ERR_NEW_CND(tx_str, E_ALLOC, exit, "failed to allocate memory for tx as string (len %d)", alloc_len)
        string_from_hex(tx_str, alloc_len, tmp->data, tmp->len);
        
        response.transactions[i]->transaction = tx_str;
        response.transactions[i]->id = req->dgs[i].id;
    }

    size_t psize = tp_messages__transactions_response__get_packed_size(&response);
    ret=array_new(psize, sizeof(uint8_t));
    ERR_NEW_CND(ret, E_ALLOC, exit, "failed to allocate %d bytes for packed transactions response", psize)
    
    tp_messages__transactions_response__pack(&response, ret->data);

exit:
    for(int i=0;i<response.n_transactions;i++) {
        if(response.transactions[i]) {
            free(response.transactions[i]->transaction);
        }
        free(response.transactions[i]);
    }
    free(response.transactions);
    array_free(&tmp);
    return ret;
}