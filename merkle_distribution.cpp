/*
* g++ -std=c++11 merkle_distribution.cpp $(pkg-config --libs libcrypto)
*/

#include <vector>
#include <sys/stat.h>
#include <iostream>
#include "assert.h"
using namespace std;

#include "src/primitives/block.cpp"
#include "src/uint256.cpp"
#include "src/hash.cpp"


// ==================================================================================


vector<uint256> BuildMerkleTree(vector<uint256> hashes)
{
	int index = 0;
	vector<uint256> vMerkleTree(hashes.size());
	for (; index < hashes.size(); index++){
		vMerkleTree[index] = hashes[index];
	}
	
	int j = 0;
	
	for (int nSize = hashes.size(); nSize > 1; nSize = (nSize + 1) / 2)
	{
        for (int i = 0; i < nSize; i += 2)
        {
            int i2 = std::min(i+1, nSize-1);
            vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]), BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
        }
        j += nSize;
    }
    
    return vMerkleTree;
}

vector<uint256> GetMerkleBranch(int nIndex, vector<uint256> vMerkleTree, int leaves)
{
    vector<uint256> vMerkleBranch;
    int j = 0;
    for (int nSize = leaves; nSize > 1; nSize = (nSize + 1) / 2)
    {
        int i = min(nIndex^1, nSize-1);
        vMerkleBranch.push_back(vMerkleTree[j+i]);
        nIndex >>= 1;
        j += nSize;
    }
    return vMerkleBranch;
}

uint256 CheckMerkleBranch(uint256 hash, const vector<uint256>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1)
        return uint256();
    for (vector<uint256>::const_iterator it(vMerkleBranch.begin()); it != vMerkleBranch.end(); ++it)
    {
        if (nIndex & 1)
            hash = Hash(BEGIN(*it), END(*it), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(*it), END(*it));
        nIndex >>= 1;
    }
    return hash;
}


// ==================================================================================


const int 				n 				=1174;	// total no. of segments.
uint256 				filehash			 ;

FILE*  					fp 					 ;  // pointer to the file segments that will be read in and hashed.
struct stat 			status 				 ;	// finding file size
int 					filesize 		=	0;  // size of the buffer
unsigned char* 			buffer 				 ;  // to read the file into
vector<uint256> 		files(n)			 ;
char*					filenamePaddingBuf 	 ;
int 					filenamePadding 	 ;
char* 					filepath 			 ;

string 					baseFilepath	=  "/home/saad/Desktop/Jerasure-1.2/Examples/Coding/";

int main() {
	filenamePaddingBuf = (char*) malloc(sizeof(char)*10);
	filepath = (char*) malloc(sizeof(char)*30 + baseFilepath.length());
	sprintf(filenamePaddingBuf, "%d", n);
	filenamePadding = strlen(filenamePaddingBuf);

	for (int i = 0; i < n; i++) {
		CHash256 hasher;

		sprintf(filepath, "%sPermacoin_%0*d.pdf", baseFilepath.c_str(), filenamePadding, i);
		fp = fopen(filepath, "rb");
		if (fp == NULL) {
			printf("===========================\nERROR: UNABLE TO OPEN FILE.\n\n");
			exit(0);
		}
		if (filesize == 0) {
			stat(filepath, &status);
			filesize = status.st_size;
			buffer = (unsigned char*)malloc(sizeof(unsigned char)*filesize);
		}

		memset((void*)buffer, 0, sizeof(buffer));
		fread((void*)buffer, sizeof(char), sizeof(buffer), fp);
		fclose(fp);
		
		hasher.Write(buffer, sizeof(buffer));
		hasher.Finalize((unsigned char*)&filehash);
		files[i] = filehash;
	}

	vector<uint256> vMerkleTree = BuildMerkleTree(files);

	uint256 rootHash = vMerkleTree.back();

	for (int i = 0; i < n; i++) {
		sprintf(filepath, "%sPermacoin_%0*d.pdf_proof.txt", baseFilepath.c_str(), filenamePadding, i);
		fp = fopen(filepath, "wb");

		vector<uint256> proof = GetMerkleBranch(i, vMerkleTree, n);
		for (int j = 0; j < proof.size(); j++) {
			fwrite(proof[j].ToString().c_str(), sizeof(char), proof[j].ToString().length(), fp);
			if (j != proof.size()-1) {fwrite("\n", sizeof(char), 1, fp);}
		}
		fclose(fp);
	}
	
	sprintf(filepath, "%sPermacoin.pdf_root_proof.txt", baseFilepath.c_str());
	fp = fopen(filepath, "wb");
	fwrite(rootHash.ToString().c_str(), sizeof(char), rootHash.ToString().length(), fp);
	fclose(fp);

	return 0;
}