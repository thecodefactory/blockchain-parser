#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include "base58.h"
#include "blockchain.h"
#include "config.h"

#ifdef USE_MYSQL
#include "db.h"
#endif


//#define BUF_LEN 384
#define BUF_LEN (16*8388608)

#define OP_0           0x00
#define OP_PUSHDATA1   0x4c
#define OP_PUSHDATA2   0x4d
#define OP_PUSHDATA4   0x4e
#define OP_1NEGATE     0x4f
#define OP_DUP         0x76
#define OP_HASH160     0xA9
#define OP_EQUALVERIFY 0x88
#define OP_CHECKSIG    0xAC


static int coin_magic = -1;
static char *coin_symbol = NULL;

coin_config_t configs[MAX_NUM_CONFIGS];

void reverse_array(unsigned char *src, unsigned char *dest, int len)
{
    int i = 0, j = 0;
    for(i = (len - 1); i > -1; i--)
    {
        dest[j++] = src[i];
    }
}

inline uint32_t read_var_int(unsigned char *data, int *var_bytes)
{
    uint32_t ret = 0;
    int offset = 0;
    uint8_t v = *((uint8_t *)data + offset);
    offset += sizeof(uint8_t);
    if (v < 0xFD)
    {
        *var_bytes = offset;
        ret = (uint32_t)v;
    }
    else
    {
        uint16_t v = *((uint16_t *)(data + offset));
        offset += sizeof(uint16_t);
        if (v < 0xFFFF)
        {
            *var_bytes = offset;
            ret = (uint32_t)v;
        }
        else
        {
            uint32_t v = *((uint32_t *)data);
            offset += sizeof(uint32_t);
            if (v < 0xFFFFFFFF)
            {
                *var_bytes = offset;
                ret = (uint32_t)v;
            }
        }
    }
    return ret;
}

int script_interpret(int is_input, unsigned char *script, int script_len, int tx_index)
{
    int i = 0, key_len = 0;
    char *script_ptr = script;
    int orig_script_len = script_len, seq_len = 0;

    while(script_ptr[0] == OP_0)
    {
        script_ptr++;
        script_len--;
    }

    printf("\t  SCRIPT INTERPRET: Script Length: %d\n", script_len);
    if ((script_len == 67) && (script_ptr[0] == 65) &&
        (script_ptr[66] == OP_CHECKSIG))
    {
        unsigned char tmp[35] = {0};
        char *public_key = tmp;
        bitcoin_public_key_to_ascii((const uint8_t *)(script + 1), tmp);
        if ((tmp[0] == '1') && (tmp[1] == '1'))
        {
            public_key = &tmp[1];
        }
        printf("\t[1]Public Key: %s\n", public_key);
    }
    else if ((script_len == 66) && (script_ptr[0] == 65) &&
        (script_ptr[65] == OP_CHECKSIG))
    {
        unsigned char public_key[35] = {0};
        bitcoin_public_key_to_ascii((const uint8_t *)script, public_key);
        printf("\t[2]Public Key: %s\n", public_key);
    }
    else if ((script_len > 24) && (script_ptr[0] == OP_DUP) &&
             (script_ptr[1] == OP_HASH160) && (script_ptr[2] == 20))
    {
        unsigned char public_key[35] = {0};
        bitcoin_ripemd160_to_ascii((const uint8_t *)(script + 3), public_key);
        printf("\t[3]Public Key: %s\n", public_key);
    }
    else if ((script_len == 5) && (script_ptr[0] == OP_DUP) &&
             (script_ptr[1] == OP_HASH160) && (script_ptr[2] == 0) &&
             (script_ptr[3] == OP_EQUALVERIFY) && (script_ptr[4] == OP_CHECKSIG))
    {
        printf("\t[4]Public Key: Found bogus data of length 0\n");
    }
    else if ((script_ptr[0] == OP_DUP) && (script_ptr[1] == OP_HASH160) &&
             (script_ptr[2] == 20) &&
             (script_ptr[23] == OP_EQUALVERIFY) && (script_ptr[24] == OP_CHECKSIG))
    {
        printf("\t[5]Public Key: ");
        for(i = 3; i < 22; i++)
        {
            printf("%.2x", script_ptr[i]);
        }
        printf("\n");
    }
    else if (script_ptr[0] < OP_PUSHDATA1)
    {
        key_len = script_ptr[0];
        script_ptr++;
        script_len--;
    }
    else if (script_ptr[0] == OP_PUSHDATA1)
    {
        key_len = script_ptr[1];
        script_ptr++;
        script_len--;
    }
    else if (script_ptr[0] == OP_PUSHDATA2)
    {
        key_len = script_ptr[1];
        script_ptr += 2;
        script_len -= 2;
    }

    if ((key_len > 0) && (key_len < script_len))
    {
        if ((script_ptr[0] == 0x30) && (script_ptr[2] == 0x02))
        {
            int seq_index = 0;
            int len = script_ptr[3];
          read_sequence:
            seq_len = script_ptr[1];
            switch(len)
            {
                case 0x1E:
                    printf("\t\t  Signature format DER_%s_1E\n", (seq_index ? "Y" : "X"));
                    break;
                case 0x1F:
                    printf("\t\t  Signature format DER_%s_1F\n", (seq_index ? "Y" : "X"));
                    break;
                case 0x20:
                    printf("\t\t  Signature format DER_%s_20\n", (seq_index ? "Y" : "X"));
                    break;
                case 0x21:
                    printf("\t\t  Signature format DER_%s_21\n", (seq_index ? "Y" : "X"));
                    break;
            }
            script_ptr += 5;
            script_ptr += seq_len;

            if (script_ptr[0] == 0x20)
            {
                seq_index++;
                if (seq_index < 2)
                {
                    goto read_sequence;
                }
            }
        }
    }

    /* else */
    /* { */
    /*     printf("\t[*]Raw Script: "); */
    /*     for(i = 0; i < script_len; i++) */
    /*     { */
    /*         printf("%.2x", script_ptr[i]); */
    /*     } */
    /*     printf("\n"); */
    /* } */
}

void print_transaction_input(transaction_input_t *input, int index)
{
    printf("\t  *** Transaction Input #%d (transactionIndex %d, scriptLength %d) ***\n",
           (index + 1), input->index, input->script_len);
    /* printf("\t    Transaction Hash: "); */
    /* for (i = 0; i < 32; i++) */
    /* { */
    /*     printf("%02x", input->hash[i]); */
    /* } */
    /* printf("\n"); */

    script_interpret(1, input->script, input->script_len, index);
    /* printf("\t  Script Length: %d\n", input->script_len); */
    /* printf("\t  Script: "); */
    /* for(i = 0; i < input->script_len; i++) */
    /* { */
    /*     printf("%.2x", input->script[i]); */
    /* } */
    /* printf("\n"); */
    /* printf("\t  Script Sequence: %x\n", input->sequence); */
}

void print_transaction_output(transaction_output_t *output, int index)
{
    printf("\t  *** Transaction Output #%d (Value %f %s) ***\n",
           (index + 1), GET_COIN_VALUE(output->value), coin_symbol);
    script_interpret(0, output->script, output->script_len, index);
}

void print_transaction(transaction_t *tx, int index)
{
    int i = 0;
    printf("\t*** Transaction #%d (Version %d, Transaction Value %f) ***\n",
           index, tx->version, GET_COIN_VALUE(tx->block_reward));

    printf("\tTransaction hash: ");
    for(i = 0; i < 32; i++)
    {
        printf("%.2x", tx->hash[i]);
    }
    printf("\n");

    printf("\tTransaction Num Inputs: %d\n", tx->num_inputs);
    for(i = 0; i < tx->num_inputs; i++)
    {
        print_transaction_input(tx->inputs[i], i);
    }

    printf("\tTransaction Num Outputs: %d\n", tx->num_outputs);
    for(i = 0; i < tx->num_outputs; i++)
    {
        print_transaction_output(tx->outputs[i], i);
    }
    printf("\tTransaction Lock Time: %d\n", tx->lock_time);
}

void print_block(block_t *block, int index)
{
    int i = 0;

    printf("********** Showing contents of Block %d **********\n", index);
    printf("Block Magic: %x\n", block->magic);
    printf("Header Length: %d\n", block->header_len);
    printf("Version: %d\n", block->version);

    printf("Block hash: ");
    for(i = 0; i < 32; i++)
    {
        printf("%.2x", block->block_hash[i]);
    }
    printf("\n");

    printf("Merkle Root: ");
    for(i = 0; i < 32; i++)
    {
        printf("%.2x", block->merkle_root[i]);
    }
    printf("\n");

    time_t t1 = (time_t)block->timestamp;
    printf("Timestamp: %s", asctime(localtime(&t1)));
    printf("Bits: %u (Hex %x)\n", block->bits, block->bits);
    printf("Nonce: %u (Hex %x)\n", block->nonce, block->nonce);

    printf("Number of Transactions: %d\n", block->num_transactions);
    printf("Total of Transaction Values: %f\n", GET_COIN_VALUE(block->block_reward));
    for(i = 0; i < block->num_transactions; i++)
    {
        print_transaction(block->transactions[i], i);
    }
}

// populates the specified block_t object and returns the offset into
// the data array to the next block (i.e. the block length consumed).
// if -1 is returned, there is not enough input data provided and more
// block data needs to be read
int read_mem_block(unsigned char *data, int len, block_t *block)
{
    int i = 0, j = 0, offset = 0;

    // make sure there's enough data to read the magic bytes
    if (4 > len)
    {
        return -1;
    }

    do
    {
        block->magic = (((data[offset+3] << 24) & 0xFF000000) | ((data[offset+2] << 16) & 0x00FF0000) |
                        ((data[offset+1] << 8) & 0x0000FF00) | (data[offset] & 0x000000FF));
        offset += sizeof(uint32_t);
    } while(block->magic != coin_magic);

    if (block->magic == coin_magic)
    {
        block->header_len = *((uint32_t *)&data[offset]);
        if (block->header_len > len)
        {
            //printf("Need more input data (got length %d)\n", len);
            return -1;
        }
        offset += sizeof(uint32_t);
        block->version = *((uint32_t *)&data[offset]);

        unsigned char hash1[BLOCK_HASH_LEN] = {0};
        compute_sha256(&data[offset], 80, hash1);
        offset += sizeof(uint32_t);

        unsigned char hash2[128] = {0};
        compute_sha256(hash1, BLOCK_HASH_LEN, hash2);

        reverse_array(hash2, block->block_hash, BLOCK_HASH_LEN);
        offset += 32;

        reverse_array(&data[offset], block->merkle_root, BLOCK_HASH_LEN);
        offset += 32;

        block->timestamp = *((uint32_t *)&data[offset]);
        offset += sizeof(uint32_t);
        block->bits = *((uint32_t *)&data[offset]);
        offset += sizeof(uint32_t);
        block->nonce = *((uint32_t *)&data[offset]);
        offset += sizeof(uint32_t);

        int var_bytes = 0;
        block->num_transactions = read_var_int(&data[offset], &var_bytes);
        offset += var_bytes;

        unsigned char *tx_start = NULL, *tx_end = NULL;

        block->transactions = (transaction_t **)malloc(
            block->num_transactions * sizeof(transaction_t *));
        for(i = 0; i < block->num_transactions; i++)
        {
            tx_start = (unsigned char *)&data[offset];

            block->transactions[i] = (transaction_t *)malloc(sizeof(transaction_t));
            block->transactions[i]->version = *((uint32_t *)&data[offset]);
            offset += sizeof(uint32_t);

            block->transactions[i]->num_inputs = read_var_int(&data[offset], &var_bytes);
            offset += var_bytes;

            block->transactions[i]->inputs = (transaction_input_t **)malloc(
                block->transactions[i]->num_inputs * sizeof(transaction_input_t *));
            for(j = 0; j < block->transactions[i]->num_inputs; j++)
            {
                block->transactions[i]->inputs[j] = (transaction_input_t *)
                    malloc(sizeof(transaction_input_t));
                // compute input transaction hash?
                //memcpy(block->transactions[i]->inputs[j]->hash, &data[offset], 32);
                offset += 32;

                block->transactions[i]->inputs[j]->index = *((uint32_t *)&data[offset]);
                offset += sizeof(uint32_t);
                block->transactions[i]->inputs[j]->script_len = read_var_int(&data[offset], &var_bytes);
                offset += var_bytes;

                if (block->transactions[i]->inputs[j]->script_len > MAX_SCRIPT_LEN)
                {
                    print_block(block, -1);
                    printf("ABORTING: Found script length of %d\n",
                           block->transactions[i]->inputs[j]->script_len);
                    exit(0);
                }
                block->transactions[i]->inputs[j]->script = (unsigned char *)malloc(
                    block->transactions[i]->inputs[j]->script_len * sizeof(unsigned char));
                memcpy(block->transactions[i]->inputs[j]->script, &data[offset],
                       block->transactions[i]->inputs[j]->script_len);
                offset += block->transactions[i]->inputs[j]->script_len;

                block->transactions[i]->inputs[j]->sequence = *((uint32_t *)&data[offset]);
                offset += sizeof(uint32_t);
            }

            block->transactions[i]->num_outputs = read_var_int(&data[offset], &var_bytes);
            offset += var_bytes;

            block->transactions[i]->outputs = (transaction_output_t **)malloc(
                block->transactions[i]->num_outputs * sizeof(transaction_output_t *));
            for(j = 0; j < block->transactions[i]->num_outputs; j++)
            {
                block->transactions[i]->outputs[j] = (transaction_output_t *)
                    malloc(sizeof(transaction_output_t));

                block->transactions[i]->outputs[j]->value = *((uint64_t *)&data[offset]);
                offset += sizeof(uint64_t);

                block->transactions[i]->block_reward += block->transactions[i]->outputs[j]->value;
                block->block_reward += block->transactions[i]->outputs[j]->value;

                block->transactions[i]->outputs[j]->script_len = read_var_int(&data[offset], &var_bytes);
                offset += var_bytes;

                block->transactions[i]->outputs[j]->script = (unsigned char *)malloc(
                    block->transactions[i]->outputs[j]->script_len * sizeof(unsigned char));
                memcpy(block->transactions[i]->outputs[j]->script, &data[offset],
                       block->transactions[i]->outputs[j]->script_len);
                offset += block->transactions[i]->outputs[j]->script_len;
            }

            block->transactions[i]->lock_time = *((uint32_t *)&data[offset]);
            offset += sizeof(uint32_t);

            tx_end = (unsigned char *)&data[offset];

            // compute the transaction hash
            compute_sha256(tx_start, (tx_end - tx_start), hash1);
            compute_sha256(hash1, TRANSACTION_HASH_LEN, hash2);

            reverse_array(hash2, block->transactions[i]->hash, TRANSACTION_HASH_LEN);
        }

        // have the parser adjust the read offset based on block header size
        //printf("HEADER LEN = %d, OFFSET = %d\n", block->header_len, offset);
        offset = block->header_len + (2 * sizeof(uint32_t));
    }
    else
    {
        printf("Coin magic does not match: %x != %x\n", coin_magic, block->magic);
    }
    return offset;
}

int main(int argc, char **argv)
{
    unsigned char *buf = (unsigned char *)malloc(BUF_LEN * sizeof(unsigned char));
    int i = 0, j = 0, offset = 0, cur_offset = 0;
    int n_read = 0, block_count = 0, block_index = 0;

    char file[512] = {0};
    char path[512] = {0};
    char *h = getenv("HOME");
    char *home = h;


    coin_config_t *cur_config = NULL;

    snprintf(path, 512, "blockchain-parser.conf");
    parse_config_file(path, configs);

    if (argc > 1)
    {
        for(i = 0; i < MAX_NUM_CONFIGS; i++)
        {
            if (strcasecmp(configs[i].name, argv[1]) == 0)
            {
                cur_config = &configs[i];
                printf("Using %s configuration\n", cur_config->name);
                break;
            }
        }
    }
    else
    {
        cur_config = &configs[0];
        printf("Using %s configuration\n", cur_config->name);
    }

    coin_magic = cur_config->magic;
    coin_symbol = cur_config->symbol;

    snprintf(file, 512, "%s/blk%.5d.dat", cur_config->blockpath, block_index);
    struct stat statbuf;
    memset(&statbuf, 0, sizeof(struct stat));
    if (stat(file, &statbuf) == 0)
    {
        FILE *f = fopen(file,"r");
        if (f)
        {
            block_t block;
            n_read = fread(buf, BUF_LEN, sizeof(char), f);
            do
            {
                if (n_read)
                {
                    memset(&block, 0, sizeof(block_t));
                    printf("Reading block %d at offset %d of %s\n", block_count, offset, file);
                    cur_offset = read_mem_block(buf + offset, (BUF_LEN - offset), &block);
                    if (cur_offset == -1)
                    {
                        fseek(f, -(BUF_LEN - offset), SEEK_CUR);
                        n_read = fread(buf, BUF_LEN, sizeof(char), f);
                        if (n_read == 0)
                        {
                            goto switch_block_file;
                        }
                        offset = 0;

                        cur_offset = read_mem_block(buf + offset, (BUF_LEN - offset), &block);
                    }
                    offset += cur_offset;
                    print_block(&block, block_count);
                    block_count++;
                    if (block_count == cur_config->numblocks)
                    {
                        break;
                    }
                }
                else
                {
                  switch_block_file:
                    fclose(f);

                    offset = 0;
                    block_index++;
                    snprintf(file, 512, "%s/blk%.5d.dat", cur_config->blockpath, block_index);
                    memset(&statbuf, 0, sizeof(struct stat));
                    printf("SWITCHING FILES: TRYING TO OPEN %s\n", file);
                    if (stat(file, &statbuf) == 0)
                    {
                        f = fopen(file,"r");
                        n_read = fread(buf, BUF_LEN, sizeof(char), f);
                    }
                    else
                    {
                        printf("Cannot open block file %s\n", file);
                        break;
                    }
                }
            } while(n_read);

            printf("TERMINATING NOW! n_read = %d, offset = %d, file = %s\n", n_read, offset, file);

            fclose(f);
        }
        else
        {
            printf("Cannot open block file %s\n", file);
        }
    }
    else
    {
        printf("Cannot find block directory %s -- please update the configuration file!\n", file);
    }
    return 0;
}
