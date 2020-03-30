#ifndef FMMODE
#include "xtz_address_test.h"
#include "utils/util.h"
#include "xtz.h"
#include <glib.h>

typedef struct {
    char* pk;
    char* addr;
} xtz_address_tv;

xtz_address_tv xtz_address_tvs[] = {
    {
        .pk = "c3dec70a8cd37f76304d69cecd783573444bb8a63ae14930bbb6778f61c5fd63",
        .addr = "tz1PDBLY2kYrz7wKHM4F13nes8pe3bBuQQS8",
    },
};

void _xtz_address_test(xtz_address_tv *tv) {
    uint8_t pk[32];
    hex_from_string(pk, 32, tv->pk);
    char address[XTZ_ADDRESS_STR_BUF_LEN];
    logger log = log_new();
    error err = NULL;
    g_assert_true(xtz_get_addr_from_pubkey(address, pk, &log, &err));
    g_assert_cmpstr(address, ==, tv->addr);
}

void xtz_address_test() {
    size_t n = sizeof(xtz_address_tvs)/sizeof(xtz_address_tv);
    for(size_t i=0;i<n;i++) {
        _xtz_address_test(&xtz_address_tvs[i]);
    }
}
#endif
