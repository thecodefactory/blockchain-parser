#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "config.h"

/*
An extremely simple and error prone config file parser.  Example format:

#########################################
section=bitcoin
# Bitcoin magic 0xD9B4BEF9
magic=3652501241
symbol=BTC
prefix=4
blockpath=/home/neillm/.bitcoin/blocks
numblocks=2
dbhost=localhost
dbport=3336
dhname=bitcoin_blockchain
dbuser=blockchain
dbpassword=blockchain
#########################################
*/

int parse_config_file(char *config_file, coin_config_t *configs)
{
    int ret = -1;
    int config_index = 0;

    char tmp[MAX_LINE_LEN] = {0};
    char line[MAX_LINE_LEN] = {0};
    struct stat statbuf;
    memset(&statbuf, 0, sizeof(struct stat));
    if (stat(config_file, &statbuf) == 0)
    {
        FILE *f = fopen(config_file,"r");
        if (f)
        {
            coin_config_t *cur_config = NULL;
            memset(configs, 0, (MAX_NUM_CONFIGS * sizeof(coin_config_t)));

            while(fgets(line, MAX_LINE_LEN, f) != NULL)
            {
                if ((line[0] == '#') || (strlen(line) < 3))
                {
                    continue;
                }

                if (strstr(line, "section="))
                {
                    cur_config = &(configs[config_index++]);
                    sscanf(line, "section=%s\n", cur_config->name);
                }
                else if (strstr(line, "magic="))
                {
                    sscanf(line, "magic=%d\n", &cur_config->magic);
                }
                else if (strstr(line, "symbol="))
                {
                    sscanf(line, "symbol=%s\n", cur_config->symbol);
                }
                else if (strstr(line, "prefix="))
                {
                    sscanf(line, "prefix=%d\n", &cur_config->prefix);
                }
                else if (strstr(line, "blockpath="))
                {
                    sscanf(line, "blockpath=%s\n", cur_config->blockpath);
                }
                else if (strstr(line, "numblocks="))
                {
                    sscanf(line, "numblocks=%d\n", &cur_config->numblocks);
                }
                else if (strstr(line, "dbhost="))
                {
                    sscanf(line, "dbhost=%s\n", cur_config->dbhost);
                }
                else if (strstr(line, "dbuser="))
                {
                    sscanf(line, "dbuser=%s\n", cur_config->dbuser);
                }
                else if (strstr(line, "dbuser="))
                {
                    sscanf(line, "dbuser=%s\n", cur_config->dbuser);
                }
                else if (strstr(line, "dbpass="))
                {
                    sscanf(line, "dbpass=%s\n", cur_config->dbpass);
                }
                else if (strstr(line, "dbport="))
                {
                    sscanf(line, "dbport=%d\n", &cur_config->dbport);
                }
            }
            fclose(f);
        }
        ret = 0;
   }
    else
    {
        fprintf(stderr, "Cannot read config file %s (does not exist)\n", config_file);
    }
    return ret;
}
