#include "allosaurus.h"
#include <stdio.h>

int main() {

    void* server = allosaurus_new_server();
    if (server != NULL) {
        printf("Server created successfully.\n");
    } else {
        printf("Failed to create server.\n");
    }
    return 0;
}

// /Users/victorh/Desktop/anoncreds/revocation_manager_ffi/agora-allosaurus-rs/target/release/libagora_allosaurus_rs.dylib