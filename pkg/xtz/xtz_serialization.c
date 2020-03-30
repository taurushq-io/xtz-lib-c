#include "xtz_serialization.h"
#include "xtz.h"

static uint8_t _get_bits_block(nn n, size_t offset, size_t len) {
    uint8_t b = 0;
    for(size_t i = 0; i<len; i++) {
        b += nn_getbit(&n, offset+i) << i;
    }
    return b;
} 

size_t xtz_serialize_n(uint8_t *stream, nn n) {
    size_t offset = 0;
    if(nn_iszero(&n)) {
        stream[offset++] = 0;
        return offset;
    }
    size_t bitlen = nn_bitlen(&n); 
    size_t sz = (bitlen+6)/7;
    size_t i = 0;
    for(i=0;i<sz-1;i++) {
        stream[offset++] = 0x80 | _get_bits_block(n, i*7, 7);
    }
    stream[offset++] = _get_bits_block(n, i*7, bitlen - (i*7));
    return offset;
}

size_t xtz_sizeof_serialize_n(nn n) {
    if(nn_iszero(&n)) return 1;
    return (nn_bitlen(&n)+6)/7;
}

size_t xtz_sizeof_serialize_reveal(const xtz_reveal_request *reveal) {
    size_t sz = 0;
    sz += XTZ_BLOCK_HASH_LEN;
    sz += 1; //tag
    sz += 1; //pubkey hash tag
    sz += XTZ_PUBKEY_HASH_LEN; // pubkey hash
    sz += xtz_sizeof_serialize_n(reveal->fee);
    sz += xtz_sizeof_serialize_n(reveal->counter);
    sz += xtz_sizeof_serialize_n(reveal->gas_limit);
    sz += 1; //storage limit is 0
    sz += 1; // pubkey tag
    sz += ED25519_PUBLIC_KEY_SIZE; // pubkey
    return sz;
}

size_t xtz_serialize_reveal(uint8_t *stream, const xtz_reveal_request *reveal) {
    size_t offset = 0;

    memcpy(stream, reveal->branch, XTZ_BLOCK_HASH_LEN);
    offset += XTZ_BLOCK_HASH_LEN;
    stream[offset++] = XTZ_REVEAL_TAG;
    stream[offset++] = XTZ_ED25519_TAG;
    memcpy(stream+offset, reveal->pubkey_hash, XTZ_PUBKEY_HASH_LEN);
    offset += XTZ_PUBKEY_HASH_LEN;
    offset += xtz_serialize_n(stream+offset, reveal->fee);
    offset += xtz_serialize_n(stream+offset, reveal->counter);
    offset += xtz_serialize_n(stream+offset, reveal->gas_limit);
    stream[offset++] = 0; //reveal has storage_limit = 0
    stream[offset++] = XTZ_ED25519_TAG;
    memcpy(stream+offset, reveal->key.public_key, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;
    
    return offset;
}

size_t xtz_sizeof_serialize_delegate(const xtz_delegation *delegate) {
    size_t sz = 0;
    sz += XTZ_BLOCK_HASH_LEN;
    sz += 1; //tag
    sz += 1; //pubkey hash tag
    sz += XTZ_PUBKEY_HASH_LEN; // pubkey hash
    sz += xtz_sizeof_serialize_n(delegate->fee);
    sz += xtz_sizeof_serialize_n(delegate->counter);
    sz += xtz_sizeof_serialize_n(delegate->gas_limit);
    sz += 1; //storage limit is 0
    sz += 1; // delegate field is present?
    if(delegate->has_delegate) {
        sz += 1;
        sz += XTZ_PUBKEY_HASH_LEN;
    }
    return sz;
}

size_t xtz_serialize_delegate(uint8_t *stream, const xtz_delegation *delegate) {
    size_t offset = 0;
    memcpy(stream, delegate->branch, XTZ_BLOCK_HASH_LEN);
    offset += XTZ_BLOCK_HASH_LEN;
    stream[offset++] = XTZ_DELEGATE_TAG;
    stream[offset++] = XTZ_ED25519_TAG;
    memcpy(stream+offset, delegate->pubkey_hash, XTZ_PUBKEY_HASH_LEN);
    offset += XTZ_PUBKEY_HASH_LEN;
    offset += xtz_serialize_n(stream+offset, delegate->fee);
    offset += xtz_serialize_n(stream+offset, delegate->counter);
    offset += xtz_serialize_n(stream+offset, delegate->gas_limit);
    stream[offset++] = 0; //delegate has storage_limit = 0
    stream[offset++] = delegate->has_delegate ? 255 : 0;
    if(delegate->has_delegate) {
        stream[offset++] = delegate->delegate.type;
        memcpy(stream+offset, delegate->delegate.hash, XTZ_PUBKEY_HASH_LEN);
        offset += XTZ_PUBKEY_HASH_LEN;
    }
    return offset;
}

size_t xtz_sizeof_serialize_entrypoint(uint8_t len) {
    return 1 + (len > 0) ? (len+1) : 0;
}

size_t xtz_sizeof_serialize_transaction(const xtz_transaction *req) {
    size_t sz = 0;
    sz += XTZ_BLOCK_HASH_LEN;
    sz += 1; //tag
    sz += 1; //pubkey hash tag
    sz += XTZ_PUBKEY_HASH_LEN; // pubkey hash
    sz += xtz_sizeof_serialize_n(req->fee);
    sz += xtz_sizeof_serialize_n(req->counter);
    sz += xtz_sizeof_serialize_n(req->gas_limit);
    sz += xtz_sizeof_serialize_n(req->storage_limit);
    sz += xtz_sizeof_serialize_n(req->amount);
    sz += XTZ_CONTRACT_ID_SIZE;
    sz += 1;
    sz += req->parameters_len;
    return sz;
}

size_t xtz_serialize_entrypoint(uint8_t *stream, uint8_t tag, uint8_t *entrypoint, uint8_t len) {
    size_t offset = 0;
    stream[offset++] = tag;
    if(tag != 255) return offset;
    memcpy(stream+offset, entrypoint, len);
    offset += len;
    return offset;
}

size_t xtz_serialize_transaction(uint8_t *stream, const xtz_transaction *req) {
    size_t offset = 0;
    memcpy(stream+offset, req->branch, XTZ_BLOCK_HASH_LEN);
    offset += XTZ_BLOCK_HASH_LEN;
    stream[offset++] = XTZ_TRANSACTION_TAG;
    stream[offset++] = XTZ_ED25519_TAG;
    memcpy(stream+offset, req->pubkey_hash, XTZ_PUBKEY_HASH_LEN);
    offset += XTZ_PUBKEY_HASH_LEN;
    offset += xtz_serialize_n(stream+offset, req->fee);
    offset += xtz_serialize_n(stream+offset, req->counter);
    offset += xtz_serialize_n(stream+offset, req->gas_limit);
    offset += xtz_serialize_n(stream+offset, req->storage_limit);
    offset += xtz_serialize_n(stream+offset, req->amount);
    memcpy(stream+offset, req->destination, XTZ_CONTRACT_ID_SIZE);
    offset += XTZ_CONTRACT_ID_SIZE;
    stream[offset++] = req->parameters_len ? 255 : 0;
    memcpy(stream+offset, req->parameters, req->parameters_len);
    offset += req->parameters_len;
    return offset;
}