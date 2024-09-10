#include "md5.h"

bool md5_hash(char *result, char *data, size_t len)
{
    struct crypto_shash *shash;
    struct shash_desc *desc;
    int ret = 0;

    shash = crypto_alloc_shash("md5", 0, 0);
    if (IS_ERR(shash)) {
        pr_err("Failed to allocate MD5 shash\n");
        return false;
    }

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(shash),
                   GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(shash);
        return false;
    }

    desc->tfm = shash;
    ret = crypto_shash_init(desc);
    if (ret) {
        pr_err("Failed to initialize MD5 shash\n");
        goto out;
    }

    ret = crypto_shash_update(desc, data, len);
    if (ret) {
        pr_err("Failed to update MD5 shash\n");
        goto out;
    }

    ret = crypto_shash_final(desc, result);
    if (ret) {
        pr_err("Failed to finalize MD5 shash\n");
        goto out;
    }

out:
    kfree(desc);
    crypto_free_shash(shash);
    return !ret;
}

// static int __init rtl_init(void)
// {
//     bool ret;
//     char result[16];
//     char data[DATA_LEN] = "a"; // Example data

//     ret = md5_hash(result, data, DATA_LEN);
//     if (ret) {
//         printk("MD5 hash of '%s' is: ", data);
//         for (int i = 0; i < 16; i++)
//             printk("%02hhx", result[i]);
//         printk("\n");
//     }

//     return 0;
// }

// static void __exit rtl_exit(void)
// {
//     // Cleanup if needed
// }

// module_init(rtl_init);
// module_exit(rtl_exit);

// MODULE_LICENSE("GPL");
