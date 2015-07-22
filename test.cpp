/*
* g++ -std=c++11 test.cpp $(pkg-config --libs libcrypto)
*/

#include <vector>
#include <sys/stat.h>
#include "src/secp256k1/include/secp256k1.h"
#include "src/uint256.cpp"
#include "src/hash.cpp"
#include "src/streams.h"
#include "src/arith_uint256.cpp"
// #include "src/key.h"
#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

// ==================================================================================

/*
* Server breaks file into n = rf segments.
* For testing, r = 2, f = 587, size_of_segment = 2048 bytes
*
* Server computes hash of every segment and publishes it. 
* During initial download, Client chooses 'l' segments to store. Client
* also downloads Merkle proofs for each segment.
* 
* A Merkle proof consists of a string of a concatenated series of 256bit hashes.
* 
* During mining, the Client generates nonce's denoted by 's'.
* The nonce affects the first challenged index which is generated, and thus all
* further challenged indexes.
* It also directly affects the "ticket" which is generated in the end.
* 
* The ticket_hasher in this code outputs a hash which is equal to
* PUZ || pk || s || (F[r[i]], sig[i], m_proof[r[i]])
* 
* For verification by other nodes, they will: 
*	check that Ticket <= Z
*	check that each File segment has a valid Merkle proof
*	compute
*		h[i]		= H(puz||pk||σ[i−1]||F[r[i]])
*	verify that σ[i] is equal to the σ[i] that is contained in the ticket.
*		σ[i] 		= sign_sk(h[i]))
*/

class CKey {
  public:
  	void MakeNewKey(bool fCompressed) {}
  	void Sign(uint256 u, vector<unsigned char> v) {}
  	CPubKey GetPubKey() const {return CPubKey();}
};

// class CPubKey {

// };

// ==================================================================================

ostream& operator<<(ostream& os, const vector<unsigned char>& v) {
	for (int i = 0; i < v.size(); i++) {
		os << v[i];
	}
	return os;
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

bool Verify(string Ticket) {
	string baseFilepath	=  "/home/saad/Desktop/Jerasure-1.2/Examples/Coding/Permacoin.pdf_root_proof.txt";
	string merkleRoot;
	ifstream fs(baseFilepath.c_str());
	getline(fs, merkleRoot);
	fs.close();

	/*
	* FORMAT
	*	pk size
	*	pk value
	*	nonce
	*	filesize
	*	proofsize (p)
	*	number of challenges (k)
	*	challenged segment number
	*	file[i] data
	*	sig[i]
	*	p merkle proofs
	*/

	// cout << "\nVERIFY\n\n " << Ticket << "\n";
	stringstream ss(Ticket);

	string s;
	char temp[10];

	// PK
	getline(ss, s);
	int pkLength = stoi(s); 
	// cout << "pkLength = " << pkLength << "\n";

	getline(ss, s);
	string pkValue = s;
	// cout << "pkValue = " << pkValue << "\n";
	CPubKey v_pk(s.begin(), s.begin()+pkLength);
	
	// NONCE
	getline(ss, s);
	int v_nNonce = stoi(s);
	// cout << "v_nNonce = " << v_nNonce << "\n";
	
	// FILESIZE
	getline(ss, s);
	int v_filesize = stoi(s);
	// cout << "v_filesize = " << v_filesize << "\n";
	
	// PROOFSIZE
	getline(ss, s);
	int v_proofsize = stoi(s);
	// cout << "v_proofsize = " << v_proofsize << "\n";
	
	// NUMBER OF CHALLENGES
	getline(ss, s);
	int v_k = stoi(s);
	// cout << "v_k = " << v_k << "\n";
	
	for (int i = 0; i < v_k; i++) {
		// CHALLENGED SEGMENT NUMBER
		getline(ss, s);
		int v_r = stoi(s);
		// cout << "v_r = " << v_r << "\n";

		// FILE DATA
		unsigned char* v_data = (unsigned char*)malloc(sizeof(unsigned char)*v_filesize);
		memset((void*)v_data, 0, v_filesize);

		int pos = ss.tellg();
		string tempStr = ss.str().substr(pos, v_filesize);
		v_data = (unsigned char*)tempStr.c_str();
		// cout << "v_data = " << tempStr << "\n\n\n\n";
		
		string tempStr2 = ss.str().substr(pos+v_filesize, ss.str().length()-pos-v_filesize);
		ss.clear();
		ss.str(tempStr2);
		ss.ignore();

		// SIGNATURE
		char* v_sig = new char[73];
		memset((void*)v_sig, 0, 73);
		ss.read(v_sig, 72);
		// cout << "v_sig = " << v_sig << "\n";
		ss.ignore();

		// MERKLE PROOF
		vector<string> v_m_proof;
		for (int j = 0; j < v_proofsize; j++) {
			getline(ss, s);
			v_m_proof.push_back(s);
			// cout << "v_m_proof[" << j << "] = " << s << "\n";
		}


		vector<uint256> proof;
		for (int j = 0; j < v_m_proof.size(); j++) {
			proof.push_back(uint256S(v_m_proof[j]));
		}
		
		CHash256 merkleHasher;
		uint256 merkleTestHash;
		merkleHasher.Write(v_data, v_filesize);
		merkleHasher.Finalize((unsigned char*)&merkleTestHash);
		uint256 supposedRootHash = CheckMerkleBranch(merkleTestHash, proof, v_r);
		assert (merkleRoot == supposedRootHash.ToString());
	}
	
	cout << "\n\nDATA SEGMENTS AND MERKLE PROOFS ARE VALID.\n\n";

	return true;
}

// ==================================================================================

CKey 					ck 					 ;  // The client's CKey. Can be used to generate pk and sk. Used for signing.
CPubKey  				pk 					 ;  // public key of client. Used for verifying.
int 					n 				=1174;	// total no. of segments.
const uint32_t 			l 				=  20;	// no. of segments each client stores.
const uint32_t 			k 				=   5;  // no. of challenges.
int 					u[l]			 	 ;  // indices of segments which the client stores.
vector<string> 			m_proof[l]			 ;  // merkle proofs of segments which the client stores.
int 					r_u_index[k+1]	 	 ; 	// values by which 'u' will be indexed
int 					r[k+1]			 	 ;  // indices of challenged segments.
uint256 				h[k] 				 ;  // hashes used for signing and generating challenge indices.
vector<unsigned char> 	sig[k+1] 			 ;  // array of signatures generated by calling ck.Sign
string 					merkleRoot			 ;  // root hash of the merkle tree

FILE*  					fp 					 ;  // pointer to the file segments that will be read in and hashed.
struct stat 			status 				 ;	// finding file size
int 					filesize 		=	0;  // size of the buffer
unsigned char* 			buffer 				 ;  // to read the file into
vector<unsigned char*> 	files(k)			 ;
char*					filenamePaddingBuf 	 ;
int 					filenamePadding 	 ;
char* 					filepath 			 ;
ifstream 				fs 					 ;

int 					nNonce 			= 	0;
string 					baseFilepath	=  "/home/saad/Desktop/Jerasure-1.2/Examples/Coding/";


// ==================================================================================

int main() {
	CHash256 u_hasher, base_hasher;
	uint256 hash, zerohash;
	uint64_t hashvalue;
	arith_uint256 hashTarget = arith_uint256().SetCompact(0x1f0fffff);
	cout << "\nHASHTARGET = " << ArithToUint256(hashTarget).ToString() << "\n\n";
		
	/*
	* baseFilepath will need to be configured somehow to point at the directory
	* where each Client stores his share of the data.
	*/
	filenamePaddingBuf = (char*) malloc(sizeof(char)*10);
	filepath = (char*) malloc(sizeof(char)*30 + baseFilepath.length());
	sprintf(filenamePaddingBuf, "%d", n);
	filenamePadding = strlen(filenamePaddingBuf);

	sprintf(filepath, "%sPermacoin.pdf_root_proof.txt", baseFilepath.c_str());
	fs.open(filepath);
	getline(fs, merkleRoot);
	fs.close();
	cout << "merkleRoot = " << merkleRoot << "\n\n";
	
	/* %%%%%%%%%%%%%
	* The wallet's key should be used, not a new one. This is a dummy implementation
	* anyways.
	*/
	ck.MakeNewKey(false);
	pk = ck.GetPubKey();
	// %%%%%%%%%%%%%

	u_hasher.Write(pk.begin(), pk.size());
		
	for (uint32_t i = 0; i < l; i++) {
	    CHash256(u_hasher).Write((unsigned char*)&i, 4).Finalize((unsigned char*)&hash);
	    hashvalue = hash.GetHash(zerohash);
	    u[i] = hashvalue % n;

		/*
		* Loading the Merkle Proofs for the stored segments.
		*/

		sprintf(filepath, "%sPermacoin_%0*d.pdf_proof.txt", baseFilepath.c_str(), filenamePadding, u[i]);
		string s;
		fs.open(filepath);
		while (getline(fs, s)) {
			m_proof[i].push_back(s);
		}
		fs.close();
	}

	/*		
		for (int i = 0; i < l; i++) {
			cout << "u[" << i << "] = " << u[i] << "\n";
			cout << "proof:\n";
			for (int j = 0; j < m_proof[i].size(); j++) {
				cout << "\t" << m_proof[i][j] << "\n";
			}
			cout << "\n";
		}
		cout << "\n";
	*/

	CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    // ss << *pblock;
    // assert(ss.size() == 80);
    // base_hasher.Write((unsigned char*)&ss[0], 76);
	base_hasher.Write(pk.begin(), pk.size());

	// for (nNonce; nNonce >= 0; nNonce++)
	// {
		CHash256 ticket_hasher;

		// %%%%%%%%%%%%%%
		for (int i = 0; i < k+1; i++) {
			sig[i] = vector<unsigned char> (72,'0'+i);
		}
		// %%%%%%%%%%%%%% To be deleted. Dummy implementation of Sign.

		// sig[0] = {0};	

		CHash256(base_hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)&hash);
		hashvalue = hash.GetHash(zerohash);
		r_u_index[0] = hashvalue % l;
		r[0] = u[r_u_index[0]];

		/*
		* 'u' contains the indices of the segments that the Client is storing.
		* r[0]			= u[H(puz||pk||s) mod l]
		* base_hasher 	= H(puz||pk)  				since this is common
		*/

		for (int i = 0; i < k; i++) {
			CHash256 hasher(base_hasher);
			hasher.Write((unsigned char*)(&(sig[i])), sig[i].size());
			sprintf(filepath, "%sPermacoin_%0*d.pdf", baseFilepath.c_str(), filenamePadding, r[i]);
			
			// cout << "r[" << i << "] = " << r[i] << "\n";

			fp = fopen(filepath, "rb");
			if (fp == NULL) {
				printf("===========================\nERROR: UNABLE TO OPEN FILE.\n\n");
				exit(0);
			}
			if (filesize == 0) {
				stat(filepath, &status);
				filesize = status.st_size;
			}

			buffer = (unsigned char*)malloc(sizeof(unsigned char)*filesize);
			memset((void*)buffer, 0, filesize);
			fread((void*)buffer, sizeof(char), filesize, fp);
			fclose(fp);
			files[i] = buffer;
			hasher.Write(buffer, filesize);
			hasher.Finalize((unsigned char*)&hash);
			h[i] = hash;
			ck.Sign(h[i], sig[i+1]);

			hasher = CHash256(base_hasher);
			hasher.Write(&(sig[i+1][0]), sig[i+1].size());
			hasher.Finalize((unsigned char*)&hash);
			hashvalue = hash.GetHash(zerohash);
			r_u_index[i+1] = hashvalue % l;
			r[i+1] = u[r_u_index[i+1]];

			/*
			* h[i]		= H(puz||pk||σ[i−1]||F[r[i]])
			* σ[i] 		= sign_sk(h[i]))
			* r[i+1] 	= u[H(puz||pk||σ[i]) mod l]
			*/


			/*
			* Validate the challenged proofs.
			*/

			vector<uint256> proof;
			for (int j = 0; j < m_proof[r_u_index[i]].size(); j++) {
				proof.push_back(uint256S(m_proof[r_u_index[i]][j]));
			}
			
			CHash256 merkleHasher;
			uint256 merkleTestHash;
			merkleHasher.Write(buffer, filesize);
			merkleHasher.Finalize((unsigned char*)&merkleTestHash);
			uint256 supposedRootHash = CheckMerkleBranch(merkleTestHash, proof, r[i]);
			assert(supposedRootHash.ToString() == merkleRoot);
		}

		CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
		stringstream ticketStream;

		/*
		* FORMAT
		*	pk size
		*	pk value
		*	nonce
		*	filesize
		*	proofsize (p)
		*	number of challenges (k)
		*	challenged segment number
		*	file[i] data
		*	sig[i]
		*	p merkle proofs
		*/

		// PK
		ss1 << pk;
		ticketStream << pk.size() << "\n" << ss1.str() << "\n";
		ss1.clear();

		// NONCE
		ticketStream << nNonce << "\n";
		ticketStream << filesize << "\n";
		ticketStream << m_proof[r_u_index[0]].size() << "\n";
		ticketStream << k << "\n";

		// FILE, SIGNATURE, PROOF
		for (int i = 0; i < k; i++) {
			ticketStream << u[r_u_index[i]] << "\n";
			ticketStream.write((char*)files[i], filesize);
			ticketStream << "\n";
			ticketStream.write((char*)(&(sig[i+1][0])), 72);
			ticketStream << "\n";
			for (int j = 0; j < m_proof[r_u_index[i]].size(); j++) {
				ticketStream << m_proof[r_u_index[i]][j] << "\n";
			}
		}
		// cout << "TS     = \n" << ticketStream.str() << "\n\n";
		// ticket_hasher.Write((unsigned char*)&ss[0], 76);
		ticket_hasher.Write((unsigned char*)(ss1.str().c_str()), ss1.size());
		ticket_hasher.Finalize((unsigned char*)&hash);
		// cout << "\nTICKET = " << hash.ToString();
		
		if (UintToArith256(hash) <= hashTarget) {
			cout << "\n\nSUCCESS\n\n";
			cout << ss1.str() << "\n";
			// break;
		}

		/*
		* Clearing used memory.
		*/
		
		for (int i = 0; i < k; i++) {
			delete files[i];
		}
	// }

	Verify(ticketStream.str());

	return 0;
}