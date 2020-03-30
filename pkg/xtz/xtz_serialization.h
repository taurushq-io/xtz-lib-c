#pragma once

#include "utils/util.h"
#include "xtz.h"

size_t xtz_serialize_n(uint8_t *stream, nn n);
size_t xtz_sizeof_serialize_n(nn n);
size_t xtz_sizeof_serialize_reveal(const xtz_reveal_request *reveal);
size_t xtz_serialize_reveal(uint8_t *stream, const xtz_reveal_request *reveal);

size_t xtz_sizeof_serialize_delegate(const xtz_delegation *delegate);
size_t xtz_serialize_delegate(uint8_t *stream, const xtz_delegation *delegate);

size_t xtz_sizeof_serialize_transaction(const xtz_transaction *transaction);
size_t xtz_serialize_transaction(uint8_t *stream, const xtz_transaction *transaction);