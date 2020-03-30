#pragma once
#include "xtz.h"
#include "utils/util.h"

array xtz_reserve(xtz_reserve_request* req, const uint8_t *seed, size_t seed_len, logger *log, error* err);