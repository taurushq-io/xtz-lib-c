#include "xtz_reserve.h"
#include "crypto/ecdsa.h"
#include "utils/util.h"

array xtz_reserve(xtz_reserve_request* req, const uint8_t *seed, size_t seed_len, logger *log, error* err) {
    ERR_CHECK_RETURN
    chknull(req)
    array ret = NULL;

    uint8_t sig[ED25519_SIGNATURE_SIZE];
    ERR_WRAP_CND(crypto_operations.ed25519_sign(sig, req->key.private_key, req->hash, 
                    SHA256_DIGEST_SIZE, log, err), exit, "failed to sign")

    char address[XTZ_ADDRESS_STR_BUF_LEN];
    ERR_WRAP_CND(xtz_get_addr_from_pubkey(address, req->key.public_key, log, err), exit, "failed to get address")

    TpMessages__ProofOfReserveResponse response;
    tp_messages__proof_of_reserve_response__init(&response);

    response.curve = TP_MESSAGES__PROOF_OF_RESERVE_RESPONSE__CURVE__Ed25519;
    response.cipher = TP_MESSAGES__PROOF_OF_RESERVE_RESPONSE__CIPHER__EDDSA;
    response.address = address;
    response.challenge = req->chall;
    response.path = req->path;
    response.challengeresponse.data = sig;
    response.challengeresponse.len = ED25519_SIGNATURE_SIZE;
    response.publickey.data = req->key.public_key_uncompressed;
    response.publickey.len = ED25519_PUBLIC_KEY_SIZE;

    size_t psize = tp_messages__proof_of_reserve_response__get_packed_size(&response);
    ret = array_new(psize, sizeof(uint8_t));
    ERR_NEW_CND(ret, E_ALLOC, exit, "failed to allocate memory for return array")
    tp_messages__proof_of_reserve_response__pack(&response, ret->data);
exit:
    return ret;
}