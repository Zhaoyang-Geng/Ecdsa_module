#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <crypto/hash.h>
#include <linux/slab.h>

#define DATA_LEN 40

bool md5_hash(char *result, char *data, size_t len);