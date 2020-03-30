#ifndef FMMODE
#include "xtz_serialization.h"
#include "xtz_serialization_test.h"
#include <glib.h>

typedef struct {
    char* in;
    char* out;
} xtz_serial_tv;

xtz_serial_tv xtz_serial_tvs[] = {
    // exactly 2 7tet
    {
        .in = "2774", //10100
        .out = "f44e",
    },
    // 2 bytes = 3 7tet
    {
        .in = "ffff",
        .out = "ffff03",
    },
    
};

void _xtz_serialization_test(xtz_serial_tv *tv) {
    size_t ilen = strlen(tv->in)/2;
    size_t olen = strlen(tv->out)/2;

    uint8_t in[100];
    hex_from_string(in, 100, tv->in);

    uint8_t out[100];
    hex_from_string(out, 100, tv->out);
    
    nn n;
    nn_init_from_buf(&n, in, ilen);
    uint8_t s[100];
    g_assert_cmpuint(xtz_sizeof_serialize_n(n), ==, olen);
    xtz_serialize_n(s, n);
    g_assert_cmpmem(s, olen, out, olen);
}

void xtz_serialization_test() {
    size_t n = sizeof(xtz_serial_tvs)/sizeof(xtz_serial_tv);
    for(size_t i=0;i<n;i++) {
        _xtz_serialization_test(&xtz_serial_tvs[i]);
    }
}
#endif
