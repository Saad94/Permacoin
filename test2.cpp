/*
* g++ -std=c++11 test2.cpp $(pkg-config --libs libcrypto)
*/

/*
* Testing uint120.
*/

#include <vector>
#include <sys/stat.h>
#include "src/secp256k1/include/secp256k1.h"
#include "src/uint256.cpp"
#include "src/hash.cpp"
#include "src/streams.h"
#include "src/arith_uint256.cpp"
// #include "src/random.cpp"
#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

int main() {
	RandAddSeedPerfmon();
    cout << "\n\n";
    vector<uint120> sig_sec(100);
    for (int k = 0; k < 100; k++) {
        char* buf = new char[33];
        memset(buf, '0', 33);
        for (int i = 0; i < 4; i++) {
            uint64_t j = GetRand(1000000000);
            // unsigned int j = rand() % 1000000000;
            snprintf(buf+8*i, 9, "%0*x", 8, j);
        }

        uint120 u1;
        u1.SetHex((char*)buf);
        sig_sec[k] = u1;
    }

    vector<uint120> sig_vMerkleTree = BuildMerkleTree(sig_sec);
    uint120 rootHash = sig_vMerkleTree.back();
    cout << "RootHash = " << rootHash.ToString() << "\n";

    for (int i = 0; i < 100; i++) {
        vector<uint120> proof = GetMerkleBranch(i, sig_vMerkleTree, 100);
        uint120 supposedRootHash = CheckMerkleBranch(sig_vMerkleTree[i], proof, i);
        assert (rootHash.ToString() == supposedRootHash.ToString());
    }


    cout << "\nPROOFS ARE VALID\n";

	return 0;
}
