#ifndef FMMODE
#include "xtz_tx_test.h"
#include <glib.h>
#include "ed25519.h"
#include "base58.h"

typedef struct {
    char* branch_hash;
    char* priv;
    char* fee;
    char* counter;
    char* gas_limit;
    char* storage_limit;
    char* amount;
    char* destination;

    char* out;
} xtz_tx_tv;

xtz_tx_tv xtz_tx_tvs[] = {
    {
        .branch_hash="6f18c7eb3b9165e7bbb32651eacc5663e67f2b650aea7e7c07a744820a80f7fa",
        .priv="3947a1bce1e759cf5e559c4027300a38bb515fea4e3222a85b29ab58e05ebad5",
        .fee="0505",
        .counter="019CA9",        
        .gas_limit="2843",
        .storage_limit="0115",
        .amount="989680",
        .destination="tz1WpkdTzGfTFdfAUAUvjLfW7USf1ANtBzKw",
        .out = "6f18c7eb3b9165e7bbb32651eacc5663e67f2b650aea7e7c07a744820a80f7fa6c00272d521751f3ccf31b4f84f8f768b20b7a0fef60850aa9b906c350950280ade20400007ab08ced65a8aafb45c67090f4944b1f51869e46006441366d7039ba4bd5bac204ba3111b0fec2f5c6aef8513ba5b6438416b63e49b8264535eb8682a454df965ae75ff4050ec89398f2400702a402e067cdb62803",
    },
};

void _xtz_tx_test(xtz_tx_tv *tv) {
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
    uint8_t storage_limit[10] = {0};
    g_assert_true(hex_from_string(storage_limit, 10, tv->storage_limit));
    uint8_t amount[10] = {0};
    g_assert_true(hex_from_string(amount, 10, tv->amount));

    xtz_transaction tx = {
        .id="test",
        .path="test",
        .parameters=NULL,
        .parameters_len=0,
    };
    error err = NULL;

    uint8_t pub[32];
    ed25519_pub_from_priv(pub, priv);
    g_assert_true(crypto_operations.blake2b(tx.pubkey_hash, 20, pub, 32, NULL, 0, &log, &err));

    memcpy(tx.branch, branch, 32);
    nn_init_from_buf(&tx.fee, fee, strlen(tv->fee)/2);
    nn_init_from_buf(&tx.counter, counter, strlen(tv->counter)/2);
    nn_init_from_buf(&tx.gas_limit, gas_limit, strlen(tv->gas_limit)/2);
    nn_init_from_buf(&tx.storage_limit, storage_limit, strlen(tv->storage_limit)/2);
    nn_init_from_buf(&tx.amount, amount, strlen(tv->amount)/2);

    uint8_t dest[27] = {0};
    size_t sz = 27;
    g_assert_true(b58tobin(dest, &sz, tv->destination, strlen(tv->destination)));
    g_assert_cmpuint(sz, ==, 27);

    if(bufncmp("\x06\xa1\x9f", dest, 3)) {
        tx.destination[0] = 0;
        tx.destination[1] = 0;
        memcpy(tx.destination+2, dest+3, 20);
    } else {
        g_assert(false);  
    } 

    memcpy(tx.key.private_key, priv, 32);

    char hex[500] = {0};
    array ret = _xtz_transaction(&tx, &log, &err);
    g_assert_nonnull(ret);
    string_from_hex(hex, 500, (uint8_t*) ret->data, ret->len);
    str_to_lower(hex);
    g_assert_cmpstr(hex, ==, tv->out);    
}

void xtz_tx_test() {
    size_t n = sizeof(xtz_tx_tvs)/sizeof(xtz_tx_tv);
    for(size_t i = 0; i < n; i++) {
        _xtz_tx_test(&xtz_tx_tvs[i]);
    }
}
#endif
