#include "pyblake2_impl_common.h"

#ifdef USE_OPTIMIZED_IMPL
#include "impl/blake2s.c"
#else
#include "impl/blake2s-ref.c"
#endif
