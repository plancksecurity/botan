#include <botan/build.h>

#ifdef BOTAN_HAS_JITTER
extern "C" {
   #include <jitterentropy.h>
}

namespace Botan {

rand_data* jitter_collector_create();
void jitter_collector_free(rand_data* collector);
void jitter_buffer(rand_data* collector, uint8_t buf[], size_t len);

}  // namespace Botan

#endif
