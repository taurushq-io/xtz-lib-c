#ifndef FMMODE
#include "xtz_reveal_test.h"
#include <glib.h>
#include "ed25519.h"

typedef struct {
    char* branch_hash;
    char* priv;
    char* fee;
    char* counter;
    char* gas_limit;

    char* out;
} xtz_reveal_tv;

xtz_reveal_tv xtz_reveal_tvs[] = {
    {
        .branch_hash="e0dfe5fc9f6b67cab315ae6750548ec88b799b579baf5733868134ac2c165473",
        .priv="3947a1bce1e759cf5e559c4027300a38bb515fea4e3222a85b29ab58e05ebad5",
        .fee="04F5",
        .counter="019CA8",        
        .gas_limit="2774",
        .out = "e0dfe5fc9f6b67cab315ae6750548ec88b799b579baf5733868134ac2c1654736b00272d521751f3ccf31b4f84f8f768b20b7a0fef60f509a8b906f44e0000c3dec70a8cd37f76304d69cecd783573444bb8a63ae14930bbb6778f61c5fd634376f51ead70ae1a90dc92aa3352d499945cb8493e3487a0d8ec2ba7bc0742bb20bb0219dc4ff1b6503f6c656a5bfe406a21c64eaaf2bd488c4bebd54a005e00",
    },
};

void _xtz_reveal_test(xtz_reveal_tv *tv) {
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


    xtz_reveal_request reveal = {
        .id="test",
        .path="test",
    };
    error err = NULL;
    uint8_t pub[32];
    ed25519_pub_from_priv(pub, priv);
    g_assert_true(crypto_operations.blake2b(reveal.pubkey_hash, 20, pub, 32, NULL, 0, &log, &err));
    memcpy(reveal.branch, branch, 32);
    nn_init_from_buf(&reveal.fee, fee, strlen(tv->fee)/2);
    nn_init_from_buf(&reveal.counter, counter, strlen(tv->counter)/2);
    nn_init_from_buf(&reveal.gas_limit, gas_limit, strlen(tv->gas_limit)/2);
    reveal.key.pubkey_len = 32;
    memcpy(reveal.key.public_key, pub, 32);
    memcpy(reveal.key.private_key, priv, 32);

    char hex[500] = {0};
    array ret = _xtz_reveal(&reveal, &log, &err);
    g_assert_nonnull(ret);
    string_from_hex(hex, 500, (uint8_t*) ret->data, ret->len);
    str_to_lower(hex);
    g_assert_cmpstr(hex, ==, tv->out);    
}

void xtz_reveal_test() {
    size_t n = sizeof(xtz_reveal_tvs)/sizeof(xtz_reveal_tv);
    for(size_t i = 0; i < n; i++) {
        _xtz_reveal_test(&xtz_reveal_tvs[i]);
    }
}
#endif
