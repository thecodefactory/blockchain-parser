#ifndef __CONFIG_H__
#define __CONFIG_H__

#define MAX_NAME_LEN       32
#define MAX_PATH_LEN      512
#define MAX_SYMBOL_LEN      5
#define MAX_NUM_CONFIGS     8
#define MAX_LINE_LEN      512
#define MAX_DB_HOST_LEN   128
#define MAX_DB_NAME_LEN    64
#define MAX_DB_USER_LEN    64
#define MAX_DB_PASS_LEN    64

typedef struct
{
    unsigned char prefix;
    int magic;
    int numblocks;
    int dbport;
    char name[MAX_NAME_LEN];
    char blockpath[MAX_PATH_LEN];
    char symbol[MAX_SYMBOL_LEN];
    char dbhost[MAX_DB_HOST_LEN];
    char dbname[MAX_DB_NAME_LEN];
    char dbuser[MAX_DB_USER_LEN];
    char dbpass[MAX_DB_PASS_LEN];
} coin_config_t;

int parse_config_file(char *config_file, coin_config_t *configs);

#endif /* __CONFIG_H__ */
