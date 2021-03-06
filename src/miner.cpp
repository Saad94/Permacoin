// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iterator>
#include <sys/stat.h>

using namespace std;


//////////////////////////////////////////////////////////////////////////////
//
// PERMACOIN
//

// ==================================================================================
// ==================================================================================


vector<uint256> BuildMerkleTree(vector<uint256> hashes)
{
    uint32_t index = 0;
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
// ==================================================================================


vector<uint120> BuildMerkleTree(vector<uint120> hashes)
{
    uint32_t index = 0;
    vector<uint120> vMerkleTree(hashes.size());
    for (; index < hashes.size(); index++){
        vMerkleTree[index] = hashes[index];
    }
    
    int j = 0;
    
    for (int nSize = hashes.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        for (int i = 0; i < nSize; i += 2)
        {
            int i2 = std::min(i+1, nSize-1);
            vMerkleTree.push_back(uint120(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]), BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2]))));
        }
        j += nSize;
    }
    
    return vMerkleTree;
}

vector<uint120> GetMerkleBranch(int nIndex, vector<uint120> vMerkleTree, int leaves)
{
    vector<uint120> vMerkleBranch;
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

uint120 CheckMerkleBranch(uint120 hash, const vector<uint120>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1)
        return uint120();
    for (vector<uint120>::const_iterator it(vMerkleBranch.begin()); it != vMerkleBranch.end(); ++it)
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
// ==================================================================================

class Ticket {
public:
    int                 nonce;
    uint32_t            filesize;
    uint32_t            sig_proofsize;
    uint120             sig_rootHash;
    uint32_t            merkle_proofsize;
    uint32_t            num_challenges;
    int*                challenged_seg_num; // [num_challenges]
    unsigned char**     files;              // [num_challenges]
    int*                sig_index;          // [num_challenges]
    uint120*            sig;                // [num_challenges]
    vector<uint120>*    sig_proof;          // [num_challenges] [sig_proofsize]
    vector<uint256>*    merkle_proof;       // [num_challenges] [merkle_proofsize]

    Ticket() {
        nonce               = 0;
        filesize            = 0;
        sig_proofsize       = 0;
        merkle_proofsize    = 0;
        num_challenges      = 0;
        challenged_seg_num  = NULL;
        files               = NULL;
        sig_index           = NULL;
        sig                 = NULL;
        sig_proof           = NULL;
        merkle_proof        = NULL;
    }

    Ticket(string input) {
        /*
            * FORMAT
            *   pk size
            *   pk value
            *   nonce
            *   filesize
            *   sig_proofsize (sp)
            *   sig_rootHash
            *   proofsize (p)
            *   number of challenges (k)
            *   challenged segment number
            *   file[i] data
            *   sig[i] index
            *   sig[i]
            *   sig_proof[i]
            *   p merkle proofs
        */

        stringstream ss(input);

        string s;

        /*
        * USER PUBLIC WALLET KEY INFORMATION, NOT CONSIDERED RIGHT NOW 
        *
            // PK
            int pkLength;
            ss >> pkLength;
            // cout << "pkLength = " << pkLength << "\n";

            getline(ss, s);
            string pkValue = s;
            // cout << "pkValue = " << pkValue << "\n";
            CPubKey v_pk(s.begin(), s.begin()+pkLength);
        */

        // NONCE
        ss >> nonce;
        
        // FILESIZE
        ss >> filesize;
        
        // SIG_PROOFSIZE
        ss >> sig_proofsize;
        
        // SIG_ROOTHASH
        ss >> s;
        sig_rootHash = uint120S(s);

        // PROOFSIZE
        ss >> merkle_proofsize;
        
        // NUMBER OF CHALLENGES
        ss >> num_challenges;
        
        const int size      = num_challenges;
        challenged_seg_num  = new int[size];
        files               = new unsigned char*[size];
        sig_index           = new int[size];
        sig                 = new uint120[size];
        sig_proof           = new vector<uint120>[size];
        merkle_proof        = new vector<uint256>[size];



        for (uint32_t i = 0; i < num_challenges; i++) {
            // CHALLENGED SEGMENT NUMBER
            ss >> challenged_seg_num[i];
            ss.ignore();
            
            // FILE DATA
            files[i] = (unsigned char*)malloc(sizeof(unsigned char)*filesize);
            memset((void*)files[i], 0, filesize);

            int pos = ss.tellg();
            string tempStr = ss.str().substr(pos, filesize);
            memcpy((void*) files[i], (void*)tempStr.c_str(), filesize);
            
            string tempStr2 = ss.str().substr(pos+filesize, ss.str().length()-pos-filesize);
            ss.clear();
            ss.str(tempStr2);
            ss.ignore();



            // SIGNATURE INDEX
            ss >> sig_index[i];
            ss.ignore();
            
            // SIGNATURE
            getline(ss, s);
            sig[i] = uint120S(s);
            
            for (uint32_t j = 0; j < sig_proofsize; j++) {
                getline(ss, s);
                sig_proof[i].push_back(uint120S(s));
            }



            // MERKLE PROOF
            for (uint32_t j = 0; j < merkle_proofsize; j++) {
                getline(ss, s);
                merkle_proof[i].push_back(uint256S(s));
            }
        }
    }

    void print() {
        cout << "\n\n";
        cout << "nonce              = "     << nonce                    << "\n";
        cout << "filesize           = "     << filesize                 << "\n";
        cout << "sig_proofsize      = "     << sig_proofsize            << "\n";
        cout << "sig_rootHash       = "     << sig_rootHash.ToString()  << "\n";
        cout << "merkle_proofsize   = "     << merkle_proofsize         << "\n";
        cout << "num_challenges     = "     << num_challenges           << "\n\n";

        for (uint32_t i = 0; i < num_challenges; i++) {
            cout << "challenged_seg_num["   << i << "] = " << challenged_seg_num[i] << "\n\n";
            cout << "files["                << i << "] = " << files[i]              << "\n\n";
            cout << "sig_index["            << i << "] = " << sig_index[i]          << "\n";
            cout << "sig["                  << i << "] = " << sig[i].ToString()     << "\n\n";
            
            string s = " ";
            for (uint32_t j = 0; j < sig_proofsize; j++) {
                if (j >= 10) {s = "";}
                cout << "sig_proof["        << i << "][" << j << "]" << s << " = " << sig_proof[i][j].ToString()       << "\n";
            }
            s = " ";
            cout << "\n";
            for (uint32_t j = 0; j < merkle_proofsize; j++) {
                if (j >= 10) {s = "";}
                cout << "merkle_proof["     << i << "][" << j << "]" << s << " = " << merkle_proof[i][j].ToString()    << "\n";
            }
            cout << "\n*****************************************\n\n";
        }
    }

    bool isNotNull() {
        return 
        (
            filesize            != 0 &&
            sig_proofsize       != 0 &&
            merkle_proofsize    != 0 &&
            num_challenges      != 0 &&
            challenged_seg_num  != NULL &&
            files               != NULL &&
            sig_index           != NULL &&
            sig                 != NULL &&
            sig_proof           != NULL &&
            merkle_proof        != NULL
        );
    }

    bool verifyMerkleProofs(string merkleRoot) {
        for (uint32_t i = 0; i < num_challenges; i++) {
            // cout << "\ni = " << i << "\n";
            // SIGNATURES
            uint120 sig_supposedRootHash = CheckMerkleBranch(sig[i], sig_proof[i], sig_index[i]);
            if (!(sig_rootHash.ToString() == sig_supposedRootHash.ToString())) {
                cout << "\n\nERROR: INVALID SIGNATURE / SIGNATURE MERKLE PROOF\n\n";
                return false;
            }


            // MERKLE PROOF
            CHash256 merkleHasher;
            uint256 merkleTestHash;
            merkleHasher.Write(files[i], filesize);
            merkleHasher.Finalize((unsigned char*)&merkleTestHash);
            uint256 supposedRootHash = CheckMerkleBranch(merkleTestHash, merkle_proof[i], challenged_seg_num[i]);
            if (!(merkleRoot == supposedRootHash.ToString())) {
                cout << "\n\nERROR: INVALID FILE SEGMENT / SEGMENT MERKLE PROOF\n\n";
                return false;
            }
        }

        return true;
    }

    uint256 hashTicket() {
        uint256 ticketHash;
        CHash256 ticket_hasher;
        string baseFilepath =  "/home/saad/Desktop/Jerasure-1.2/Examples/Coding/Permacoin.pdf_root_proof.txt";
        string merkleRoot;
        ifstream fs(baseFilepath.c_str());
        getline(fs, merkleRoot);
        fs.close();

        if (verifyMerkleProofs(merkleRoot)) {
            stringstream ticketStream;

            ticketStream << nonce                           << "\n";
            ticketStream << filesize                        << "\n";
            ticketStream << sig_proofsize                   << "\n";
            ticketStream << sig_rootHash.ToString()         << "\n";
            ticketStream << merkle_proofsize                << "\n";
            ticketStream << num_challenges                  << "\n";

            // FILE, SIGNATURE, PROOF
            for (uint32_t i = 0; i < num_challenges; i++) {
                ticketStream << challenged_seg_num[i] << "\n";
                ticketStream.write((char*)files[i], filesize);
                ticketStream << "\n";

                ticketStream << sig_index[i] << "\n";
                ticketStream << sig[i].ToString() << "\n";
                for (uint32_t j = 0; j < sig_proofsize; j++) {
                    ticketStream << sig_proof[i][j].ToString() << "\n";
                }
                
                for (uint32_t j = 0; j < merkle_proofsize; j++) {
                    ticketStream << merkle_proof[i][j].ToString() << "\n";
                }
            }

            // ticket_hasher.Write((unsigned char*)&ss[0], 76);
            ticket_hasher.Write((unsigned char*)(ticketStream.str().c_str()), ticketStream.str().length());
            ticket_hasher.Finalize((unsigned char*)&ticketHash);
        }

        cout << "\nTICKET = " << ticketHash.ToString();
        return ticketHash;
    }
};

// ==================================================================================
// ==================================================================================


bool Verify(string input, arith_uint256 difficultyTarget) {
    Ticket ticket(input);
    // ticket.print();
    if (UintToArith256(ticket.hashTicket()) <= difficultyTarget) {
        cout << "\n\nVALIDATED    -    TICKET IS LESS THAN TARGET.\n\n";
        return true;
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.
// The COrphan class keeps track of these 'temporary orphans' while
// CreateBlock is figuring out which transactions to include.
//
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    CFeeRate feeRate;
    double dPriority;

    COrphan(const CTransaction* ptxIn) : ptx(ptxIn), feeRate(0), dPriority(0)
    {
    }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee rate, so:
typedef boost::tuple<double, CFeeRate, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }

    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

void UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
}

CBlockTemplate* CreateNewBlock(const CScript& scriptPubKeyIn)
{
    const CChainParams& chainparams = Params();
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (Params().MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    // Create coinbase tx
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        CCoinsViewCache view(pcoinsTip);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
            const CTransaction& tx = mi->second.GetTx();
            if (tx.IsCoinBase() || !IsFinalTx(tx, nHeight, pblock->nTime))
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            CAmount nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        LogPrintf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].GetTx().vout[txin.prevout.n].nValue;
                    continue;
                }
                const CCoins* coins = view.AccessCoins(txin.prevout.hash);
                assert(coins);

                CAmount nValueIn = coins->vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = nHeight - coins->nHeight;

                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);

            uint256 hash = tx.GetHash();
            mempool.ApplyDeltas(hash, dPriority, nTotalIn);

            CFeeRate feeRate(nTotalIn-tx.GetValueOut(), nTxSize);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->feeRate = feeRate;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, feeRate, &mi->second.GetTx()));
        }

        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            CFeeRate feeRate = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Skip free transactions if we're past the minimum block size:
            const uint256& hash = tx.GetHash();
            double dPriorityDelta = 0;
            CAmount nFeeDelta = 0;
            mempool.ApplyDeltas(hash, dPriorityDelta, nFeeDelta);
            if (fSortedByFee && (dPriorityDelta <= 0) && (nFeeDelta <= 0) && (feeRate < ::minRelayTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritise by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!view.HaveInputs(tx))
                continue;

            CAmount nTxFees = view.GetValueIn(tx)-tx.GetValueOut();

            nTxSigOps += GetP2SHSigOpCount(tx, view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Note that flags: we don't want to set mempool/IsStandard()
            // policy here, but we still have to ensure that the block we
            // create only contains transactions that are valid in new blocks.
            CValidationState state;
            if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true))
                continue;

            UpdateCoins(tx, state, view, nHeight);

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                LogPrintf("priority %.1f fee %s txid %s\n",
                    dPriority, feeRate.ToString(), tx.GetHash().ToString());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->feeRate, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u\n", nBlockSize);

        // Compute final coinbase transaction.
        txNew.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0;
        pblock->vtx[0] = txNew;
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(pblock, Params().GetConsensus(), pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, Params().GetConsensus());
        pblock->nNonce         = 0;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        CValidationState state;
        if (!TestBlockValidity(state, *pblock, pindexPrev, false, false))
            throw std::runtime_error("CreateNewBlock(): TestBlockValidity failed");
    }

    return pblocktemplate.release();
}

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//
bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash)
{
    CKey                    ck                   ;  // The client's CKey. Can be used to generate pk and sk. Used for signing.
    CPubKey                 pk                   ;  // public key of client. Used for verifying.
    int                     n               =1174;  // total no. of segments.
    const uint32_t          l               =  20;  // no. of segments each client stores.
    const uint32_t          k               =   5;  // no. of challenges.
    int                     u[l]                 ;  // indices of segments which the client stores.
    vector<string>          m_proof[l]           ;  // merkle proofs of segments which the client stores.
    int                     r_u_index[k+1]       ;  // values by which 'u' will be indexed
    int                     r[k+1]               ;  // indices of challenged segments.
    uint256                 h[k]                 ;  // hashes used for signing and generating challenge indices.
    string                  merkleRoot           ;  // root hash of the merkle tree

    FILE*                   fp                   ;  // pointer to the file segments that will be read in and hashed.
    struct stat             status               ;  // finding file size
    int                     filesize        =   0;  // size of the buffer
    unsigned char*          buffer               ;  // to read the file into
    vector<unsigned char*>  files(k)             ;
    char*                   filenamePaddingBuf   ;
    int                     filenamePadding      ;
    char*                   filepath             ;
    ifstream                fs                   ;
    stringstream            ticketStream         ;

    string                  baseFilepath    =  "/home/saad/Desktop/Jerasure-1.2/Examples/Coding/";

    const uint32_t          sig_numKeys         = 100            ;  // number of leaves in the signature merkle tree
    const uint32_t          sig_numChallenges   = k+sig_numKeys/5;
    vector<uint120>         sig_keys(sig_numKeys)                ;  // leaves on the signature merkle tree
    vector<uint120>         sig_vMerkleTree                      ;  // the signature merkle tree
    uint120                 sig_rootHash                         ;  // root hash of the signature merkle tree
    set<int>                sig_signer_indexes                   ;  // signer's current unused strings
    vector<int>             sig_chosen_indexes                   ;  // vector of signature indexes
    vector<uint120>         sig_chosen_proofs[sig_numChallenges] ;  // merkle proofs of signatures

    // ==================================================================================
    // FPS SCHEME
    //

    RandAddSeedPerfmon();
    for (uint32_t i = 0; i < sig_numKeys; i++) {
        char* buf = new char[33];
        memset(buf, '0', 33);
        for (int j = 0; j < 4; j++) {
            uint64_t k = GetRand(1000000000);
            snprintf(buf+8*j, 9, "%0*x", 8, k);
        }

        uint120 u1;
        u1.SetHex((char*)buf);
        sig_keys[i] = u1;
    }
    cout << "\n\n";

    sig_vMerkleTree = BuildMerkleTree(sig_keys);
    sig_rootHash = sig_vMerkleTree.back();
    // cout << "RootHash = " << sig_rootHash.ToString() << "\n";

    //
    // FPS SCHEME
    // ==================================================================================


    CHash256 u_hasher, base_hasher;
    uint256 hash, zerohash;
    uint64_t hashvalue;
    // arith_uint256 hashTarget = arith_uint256().SetCompact(0x1e0fffff);
    // cout << "\nHASHTARGET = " << ArithToUint256(hashTarget).ToString() << "\n\n";
        
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
    // cout << "merkleRoot = " << merkleRoot << "\n\n";
    
    /* %%%%%%%%%%%%%
    * The wallet's key should be used, not a new one. This is a dummy implementation
    * anyways.
    */
    // ck.MakeNewKey(false);
    // pk = ck.GetPubKey();
    // u_hasher.Write(pk.begin(), pk.size());
    // %%%%%%%%%%%%%

    for (uint32_t i = 0; i < l; i++) {
        CHash256(u_hasher).Write((unsigned char*)&i, 4).Finalize((unsigned char*)&hash);
        hashvalue = hash.GetHash(zerohash);
        u[i] = hashvalue % n;

        /*
        * 'u' contains the indices of the segments that the Client is storing.
        * u[i] = H(pk||i) mod n
        */

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

        /* TESTING */
            // for (uint32_t i = 0; i < l; i++) {
            //     cout << "u[" << i << "] = " << u[i] << "\n";
            //     cout << "proof:\n";
            //     for (int j = 0; j < m_proof[i].size(); j++) {
            //         cout << "\t" << m_proof[i][j] << "\n";
            //     }
            //     cout << "\n";
            // }
            // cout << "\n";
        /* TESTING */

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock;
    // assert(ss.size() == 80);
    // base_hasher.Write((unsigned char*)&ss[0], 76);
    // base_hasher.Write(pk.begin(), pk.size());

    while (1)
    {
        nNonce++;
        CHash256 ticket_hasher;

        /* --- FPS SCHEME --- */  

        int sig_curNumKeys = sig_numKeys;
        sig_signer_indexes.clear();
        sig_chosen_indexes.clear();

        for (uint32_t i = 0; i < sig_numChallenges; i++) {
            sig_chosen_proofs[i].clear();
        }

        for (uint32_t i = 0; i < sig_numKeys; i++) {
            sig_signer_indexes.insert(i);
        }

        /* --- FPS SCHEME --- */

        CHash256(base_hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)&hash);
        hashvalue = hash.GetHash(zerohash);
        r_u_index[0] = hashvalue % l;
        r[0] = u[r_u_index[0]];

        /*
        * 'u' contains the indices of the segments that the Client is storing.
        * r[0]          = u[H(puz||pk||s) mod l]
        * base_hasher   = H(puz||pk)                since this is common
        */

        for (uint32_t i = 0; i < k; i++) {
            CHash256 hasher(base_hasher);
            if (i != 0) {
                hasher.Write(sig_vMerkleTree[sig_chosen_indexes.back()].begin(), 15);
                for (uint32_t j = 0; j < sig_chosen_proofs[i-1].size(); j++) {
                    hasher.Write(sig_chosen_proofs[i-1][j].begin(), 15);
                }
            } else {
                uint120 temp_u;
                hasher.Write(temp_u.begin(), 15);
            }
            
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
            // if (i == 0) {
            //     cout << "BUFFER = \n" << buffer << "\n\n\n\n";
            // }
            
            hasher.Write(buffer, filesize);
            hasher.Finalize((unsigned char*)&hash);
            h[i] = hash;

            /* --- FPS SCHEME --- */  

            int sig_i = hash.GetHash(zerohash) % sig_curNumKeys;
            sig_curNumKeys--;
            set<int>::iterator it = sig_signer_indexes.begin();
            advance(it, sig_i);
            sig_chosen_indexes.push_back(*it);
            sig_signer_indexes.erase(it);

            sig_chosen_proofs[i] = GetMerkleBranch(sig_chosen_indexes.back(), sig_vMerkleTree, sig_numKeys);

                /* TESTING */
                    // uint120 supposedRootHash1 = CheckMerkleBranch(sig_vMerkleTree[sig_chosen_indexes.back()], sig_chosen_proofs[i], sig_chosen_indexes.back());
                    // assert (sig_rootHash.ToString() == supposedRootHash1.ToString());

                    // cout << "INDEX = " << sig_chosen_indexes.back() << "\n";
                    // cout << "VALUE = " << sig_vMerkleTree[sig_chosen_indexes.back()].ToString() << "\n";
                    // cout << "PROOF = " << "\n";
                    // for (int x = 0; x < sig_chosen_proofs[i].size(); x++) {
                    //     cout << "        " << sig_chosen_proofs[i][x].ToString() << "\n";
                    // }
                    // cout << "\n\n";
                /* TESTING */

            /* --- FPS SCHEME --- */  

            hasher = CHash256(base_hasher);
            hasher.Write(sig_vMerkleTree[sig_chosen_indexes.back()].begin(), 15);
            for (uint32_t j = 0; j < sig_chosen_proofs[i].size(); j++) {
                hasher.Write(sig_chosen_proofs[i][j].begin(), 15);
            }
            hasher.Finalize((unsigned char*)&hash);
            hashvalue = hash.GetHash(zerohash);
            r_u_index[i+1] = hashvalue % l;
            r[i+1] = u[r_u_index[i+1]];

            /*
            * h[i]      = H(puz||pk||σ[i−1]||F[r[i]])
            * σ[i]      = FPS Signature
            * r[i+1]    = u[H(puz||pk||σ[i]) mod l]
            */


                /* TESTING */
                    // vector<uint256> proof;
                    // for (uint32_t j = 0; j < m_proof[r_u_index[i]].size(); j++) {
                    //     proof.push_back(uint256S(m_proof[r_u_index[i]][j]));
                    //     // cout << "proof[" << j << "] = << " << proof.back().ToString() << "\n";
                    // }
                    // // cout << "\n";
                    // CHash256 merkleHasher;
                    // uint256 merkleTestHash;
                    // merkleHasher.Write(buffer, filesize);
                    // merkleHasher.Finalize((unsigned char*)&merkleTestHash);
                    // cout << "file_hash = " << merkleTestHash.ToString() << "\n";
                    // uint256 supposedRootHash = CheckMerkleBranch(merkleTestHash, proof, r[i]);
                    // assert(supposedRootHash.ToString() == merkleRoot);
                /* TESTING */
        }

        CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
        ticketStream.str("");

        /*
        * FORMAT
        *   pk size
        *   pk value
        *   nonce
        *   filesize
        *   sig_proofsize (sp)
        *   sig_rootHash
        *   proofsize (p)
        *   number of challenges (k)
        *   challenged segment number
        *   file[i] data
        *   sig[i] index
        *   sig[i]
        *   sig_proof[i]
        *   p merkle proofs
        */

        // PK
        // ss1 << pk;
        // ticketStream << pk.size() << "\n" << ss1.str() << "\n";
        ss1.clear();

        // NONCE
        ticketStream << nNonce                          << "\n";
        ticketStream << filesize                        << "\n";
        ticketStream << sig_chosen_proofs[0].size()     << "\n";
        ticketStream << sig_rootHash.ToString()         << "\n";
        ticketStream << m_proof[r_u_index[0]].size()    << "\n";
        ticketStream << k                               << "\n";

        // FILE, SIGNATURE, PROOF
        for (uint32_t i = 0; i < k; i++) {
            ticketStream << u[r_u_index[i]] << "\n";
            ticketStream.write((char*)files[i], filesize);
            ticketStream << "\n";

            ticketStream << sig_chosen_indexes[i] << "\n";
            ticketStream << sig_vMerkleTree[sig_chosen_indexes[i]].ToString() << "\n";
            for (uint32_t j = 0; j < sig_chosen_proofs[i].size(); j++) {
                ticketStream << sig_chosen_proofs[i][j].ToString() << "\n";
            }
            
            for (uint32_t j = 0; j < m_proof[r_u_index[i]].size(); j++) {
                ticketStream << m_proof[r_u_index[i]][j] << "\n";
            }
        }
        // cout << "TS     = \n" << ticketStream.str() << "\n\n";
        // ticket_hasher.Write((unsigned char*)&ss[0], 76);
        ticket_hasher.Write((unsigned char*)(ticketStream.str().c_str()), ticketStream.str().length());
        ticket_hasher.Finalize((unsigned char*)phash);
        cout << "\nTICKET = " << phash->ToString();
        
        /*
        * Clearing used memory.
        */
        
        // Files are loaded and deleted on each iteration which is inefficient.
        // However, the paper states that each client should be storing around 4GB
        // of files. If we load all the files into memory and keep them there, unless
        // the client has more than 4GB of RAM, this will not work.
        for (uint32_t i = 0; i < k; i++) {
            delete files[i];
        }

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0) {
            return true;
        }

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xfff) == 0) {
            return false;
        }
    }

    return true;


    // ORIGINAL SCANHASH FUNCTION

        // // Write the first 76 bytes of the block header to a double-SHA256 state.
        // CHash256 hasher;
        // CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        // ss << *pblock;
        // assert(ss.size() == 80);
        // hasher.Write((unsigned char*)&ss[0], 76);

        // while (true) {
        //     nNonce++;

        //     // Write the last 4 bytes of the block header (the nonce) to a copy of
        //     // the double-SHA256 state, and compute the result.
        //     CHash256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        //     // Return the nonce if the hash has at least some zero bits,
        //     // caller will check if it has enough to reach the target
        //     if (((uint16_t*)phash)[15] == 0)
        //         return true;

        //     // If nothing found after trying for a while, return -1
        //     if ((nNonce & 0xfff) == 0)
        //         return false;
        // }
}

CBlockTemplate* CreateNewBlockWithKey(CReserveKey& reservekey)
{
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;

    CScript scriptPubKey = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
    return CreateNewBlock(scriptPubKey);
}

static bool ProcessBlockFound(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("BitcoinMiner: generated block is stale");
    }

    // Remove key from key pool
    reservekey.KeepKey();

    // Track how many getdata requests this block gets
    {
        LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(state, NULL, pblock, true, NULL))
        return error("BitcoinMiner: ProcessNewBlock, block not accepted");

    return true;
}

void static BitcoinMiner(CWallet *pwallet)
{
    LogPrintf("BitcoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("bitcoin-miner");
    const CChainParams& chainparams = Params();

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    try {
        while (true) {
            if (chainparams.MiningRequiresPeers()) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    bool fvNodesEmpty;
                    {
                        LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty && !IsInitialBlockDownload())
                        break;
                    MilliSleep(1000);
                } while (true);
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            CBlockIndex* pindexPrev = chainActive.Tip();

            auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlockWithKey(reservekey));
            if (!pblocktemplate.get())
            {
                LogPrintf("Error in BitcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("Running BitcoinMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search
            //
            int64_t nStart = GetTime();
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);
            uint256 hash;
            uint32_t nNonce = 0;
            while (true) {
                // Check if something found
                if (ScanHash(pblock, nNonce, &hash))
                {
                    if (UintToArith256(hash) <= hashTarget)
                    {
                        // Found a solution
                        pblock->nNonce = nNonce;
                        assert(hash == pblock->GetHash());

                        SetThreadPriority(THREAD_PRIORITY_NORMAL);
                        LogPrintf("BitcoinMiner:\n");
                        LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex());
                        ProcessBlockFound(pblock, *pwallet, reservekey);
                        SetThreadPriority(THREAD_PRIORITY_LOWEST);

                        // In regression test mode, stop mining after a block is found.
                        if (chainparams.MineBlocksOnDemand())
                            throw boost::thread_interrupted();

                        break;
                    }
                }

                // Check for stop or if block needs to be rebuilt
                boost::this_thread::interruption_point();
                // Regtest mode doesn't require peers
                if (vNodes.empty() && chainparams.MiningRequiresPeers())
                    break;
                if (nNonce >= 0xffff0000)
                    break;
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip())
                    break;

                // Update nTime every few seconds
                UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks)
                {
                    // Changing pblock->nTime can change work required on testnet:
                    hashTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("BitcoinMiner terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("BitcoinMiner runtime error: %s\n", e.what());
        return;
    }
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;

    if (nThreads < 0) {
        // In regtest threads defaults to 1
        if (Params().DefaultMinerThreads())
            nThreads = Params().DefaultMinerThreads();
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
}











int main() {
    CBlockHeader *pblock = new CBlockHeader();
    uint32_t nNonce = 0; 
    uint256 *phash = new uint256();
    arith_uint256 hashTarget = arith_uint256().SetCompact(0x1e0fffff);

    // ScanHash(pblock, nNonce, phash);

    while (true) {
        if (ScanHash(pblock, nNonce, phash))
        {
            cout << "\n\nHASH = " << phash->ToString() << "\n\n";
            if (UintToArith256(*phash) <= hashTarget)
            {
                cout << "\n\nSUCCESS\n\n";
                break;
            }
        } else {
            cout << "\n\nFALSE\n\n";
        }
    }
    

    // RandAddSeedPerfmon();
    // cout << "\n\n";
    // vector<uint120> sig_sec(100);
    // for (int k = 0; k < 100; k++) {
    //     char* buf = new char[33];
    //     memset(buf, '0', 33);
    //     for (int i = 0; i < 4; i++) {
    //         uint64_t j = GetRand(1000000000);
    //         // unsigned int j = rand() % 1000000000;
    //         snprintf(buf+8*i, 9, "%0*x", 8, j);
    //     }

    //     uint120 u1;
    //     u1.SetHex((char*)buf);
    //     sig_sec[k] = u1;
    // }

    // vector<uint120> sig_vMerkleTree = BuildMerkleTree(sig_sec);
    // uint120 sig_rootHash = sig_vMerkleTree.back();
    // cout << "RootHash = " << sig_rootHash.ToString() << "\n";

    // set<int> sig_signer_indexes;
    // for (int i = 0; i < 100; i++) {
    //     sig_signer_indexes.insert(i);
    // }


//     for (int i = 0; i < 100; i++) {
//         vector<uint120> proof = GetMerkleBranch(i, sig_vMerkleTree, 100);
        // uint120 supposedRootHash = CheckMerkleBranch(sig_vMerkleTree[i], proof, i);
        // assert (rootHash.ToString() == supposedRootHash.ToString());
//     }

//     cout << "\nPROOFS ARE VALID\n";

    return 0;
}


#endif // ENABLE_WALLET
