#ifndef __BLOCKCHAIN_H__
#define __BLOCKCHAIN_H__

#define BITCOIN_MAGIC                  0xD9B4BEF9
#define BITCOIN_SYMBOL                      "BTC"

#define BLOCK_HASH_LEN                         32
#define MERKLE_ROOT_LEN                        32
#define TRANSACTION_HASH_LEN                   32

#define MAX_SCRIPT_LEN                       8192

#define GET_COIN_VALUE(x) (float)x / 100000000

typedef struct
{
    unsigned char hash[TRANSACTION_HASH_LEN];
    uint32_t index;
    uint32_t script_len;
    unsigned char *script;
    uint32_t sequence;
} transaction_input_t;

typedef struct
{
    uint64_t value;
    uint32_t script_len;
    unsigned char *script;
} transaction_output_t;

typedef struct
{
    uint32_t version;
    uint32_t num_inputs;
    transaction_input_t **inputs;
    uint32_t num_outputs;
    transaction_output_t **outputs;
    uint32_t lock_time;

    // not a part of the blockchain
    // tallies up transaction totals
    uint64_t block_reward;

    // the computed transaction hash
    unsigned char hash[TRANSACTION_HASH_LEN];
} transaction_t;

typedef struct
{
    uint32_t magic;
    uint32_t header_len;
    uint32_t version;
    unsigned char block_hash[BLOCK_HASH_LEN];
    unsigned char merkle_root[MERKLE_ROOT_LEN];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;

    uint32_t num_transactions;
    transaction_t **transactions;

    // not a part of the blockchain
    // tallies up transaction totals for the block
    uint64_t block_reward;
} block_t;

#endif /* __BLOCKCHAIN_H__ */
