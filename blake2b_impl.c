#include "pyblake2_impl_common.h"

#ifdef USE_OPTIMIZED_IMPL
#include "impl/blake2b.c"
#else
#include "impl/blake2b-ref.c"
#endif
