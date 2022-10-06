#include <vector>
#include <chrono>
#include <iostream>
#include <string>
#include <typeinfo>

#include "../src/SEAL_Cipher.h"
#include "../src/pasta_3_plain.h"  // for PASTA_params
#include "../src/pasta_3_seal.h"
#include "../src/utils.h"
#include "../src/sealhelper.h"

#define NUM_RUN 50 // number of runs to get the average measurements
#define NUM_VEC 10 // number of vectors the user have

static const bool USE_BATCH = true;

int main() {
    print_example_banner("Experiments: 2-party HHE User");
}