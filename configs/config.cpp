#include <stdint.h>
#include <cstddef>

namespace config
{
    uint64_t plain_mod = 65537;
    uint64_t mod_degree = 16384;
    int seclevel = 128;
    bool use_bsgs = false;
    uint64_t NUM_RUN = 1;
    uint64_t NUM_VEC = 2;
    bool USE_BATCH = true;
    size_t user_vector_size = 4;
}