#include "jitter.h"

#ifdef BOTAN_HAS_JITTER

   #include <memory>

namespace Botan {

rand_data* jitter_collector_create() {
   static int result = jent_entropy_init();

   if(result == 0) {
      return jent_entropy_collector_alloc(1, 0);
   } else {
      return nullptr;
   }
}

void jitter_collector_free(rand_data* collector) {
   if(collector) {
      jent_entropy_collector_free(collector);
   }
}

void jitter_buffer(rand_data* collector, uint8_t buf[], size_t len) {
   if(!collector) {
      return;
   }

   if(len <= 0) {
      return;
   }

   std::unique_ptr<char[]> jitter_data{new char[len]};
   if(!jitter_data) {
      return;
   }

   ssize_t num_bytes = jent_read_entropy(collector, jitter_data.get(), len);
   if(num_bytes < 0) {
      return;
   }
   if(static_cast<size_t>(num_bytes) < len) {
      return;
   }

   for(auto i = 0; i < len; ++i) {
      buf[i] ^= jitter_data[i];
   }
}

}  // namespace Botan

#endif
