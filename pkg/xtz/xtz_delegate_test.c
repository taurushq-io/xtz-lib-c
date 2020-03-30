#ifndef FMMODE
#include "xtz_delegate_test.h"
#include <glib.h>
#include "ed25519.h"

typedef struct {
    char* branch_hash;
    char* priv;
    char* fee;
    char* counter;
    char* gas_limit;

    char* delegate;

    char* out;
} xtz_delegate_tv;

xtz_delegate_tv xtz_delegate_tvs[] = {
    {
        .branch_hash="70eb684eb06595e09c895c5fd6ea125b648575722a92999765acf13ab3a4b1ac",
        .priv="3947a1bce1e759cf5e559c4027300a38bb515fea4e3222a85b29ab58e05ebad5",
        .fee="04EA",
        .counter="019CA9",        
        .gas_limit="2774",
        .delegate="2cca28ab019ae2d8c26f4ce4924cad67a2dc6618",
        .out = "70eb684eb06595e09c895c5fd6ea125b648575722a92999765acf13ab3a4b1ac6e00272d521751f3ccf31b4f84f8f768b20b7a0fef60ea09a9b906f44e00ff002cca28ab019ae2d8c26f4ce4924cad67a2dc661891ebddfd65f0c3fd7c629e1165e7cd0900d027ae8733c2251661663e15067120a5bec268d236e76d33dfa9ce86ae99458f8c2a7188252121274a816c14b0530e",
    },
    {
        .branch_hash="02d6951dfe9be15f101d98c47118ce1d506e77db087d16d6c5700c7815006313",
        .priv="3947a1bce1e759cf5e559c4027300a38bb515fea4e3222a85b29ab58e05ebad5",
        .fee="04D5",
        .counter="019CA9",        
        .gas_limit="2774",
        .delegate=NULL,
        .out = "02d6951dfe9be15f101d98c47118ce1d506e77db087d16d6c5700c78150063136e00272d521751f3ccf31b4f84f8f768b20b7a0fef60d509a9b906f44e000047b50390515dc50321acb1757cb97dd3012f0637ead5872e3a597c28ef1c921b936a02702fb92804227c3a04e12295dfcff4051fe5c40f2a053a7f7559bb5903",
    },    
};

void _xtz_delegate_test(xtz_delegate_tv *tv) {
    logger log = log_new();
    uint8_t priv[32];
    g_assert_true(hex_from_string(priv, 32, tv->priv));
    uint8_t branch[32];
    g_assert_true(hex_from_string(branch, 32, tv->branch_hash));
    uint8_t fee[10] = {0};
    g_assert_true(hex_from_string(fee, 10, tv->fee));
    uint8_t counter[10] = {0};
    g_assert_true(hex_from_string(counter, 10, tv->counter));
    uint8_t gas_limit[10] = {0};
    g_assert_true(hex_from_string(gas_limit, 10, tv->gas_limit));

    xtz_delegation delegate = {
        .id="test",
        .path="test",
    };
    error err = NULL;
    uint8_t pub[32];
    ed25519_pub_from_priv(pub, priv);
    g_assert_true(crypto_operations.blake2b(delegate.pubkey_hash, 20, pub, 32, NULL, 0, &log, &err));
    memcpy(delegate.branch, branch, 32);
    nn_init_from_buf(&delegate.fee, fee, strlen(tv->fee)/2);
    nn_init_from_buf(&delegate.counter, counter, strlen(tv->counter)/2);
    nn_init_from_buf(&delegate.gas_limit, gas_limit, strlen(tv->gas_limit)/2);
    if(tv->delegate) {
        delegate.has_delegate = true;
        g_assert_true(hex_from_string(delegate.delegate.hash, XTZ_PUBKEY_HASH_LEN, tv->delegate));
        delegate.delegate.type = XTZ_ED25519_TAG;
    } else {
        delegate.has_delegate = false;        
    }
    delegate.key.pubkey_len = 32;
    memcpy(delegate.key.public_key, pub, 32);
    memcpy(delegate.key.private_key, priv, 32);

    char hex[500] = {0};
    array ret = _xtz_delegation(&delegate, &log, &err);
    g_assert_nonnull(ret);
    string_from_hex(hex, 500, (uint8_t*) ret->data, ret->len);
    str_to_lower(hex);
    g_assert_cmpstr(hex, ==, tv->out);    
}

void xtz_delegate_test() {
    size_t n = sizeof(xtz_delegate_tvs)/sizeof(xtz_delegate_tv);
    for(size_t i = 0; i < n; i++) {
        _xtz_delegate_test(&xtz_delegate_tvs[i]);
    }
}
#endif
