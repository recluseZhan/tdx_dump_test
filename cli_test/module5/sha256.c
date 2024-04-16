#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <crypto/sha256_base.h>

#define SIGNATURE_SIZE 32 // Size of SHA-256 hash in bytes

static char *message = "hello"; // Message to be signed

static int __init digital_signature_init(void)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    unsigned char digest[SIGNATURE_SIZE];
    int ret = 0;

    // Allocate space for the hash digest
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate transform\n");
        return PTR_ERR(tfm);
    }

    // Calculate the size of shash_desc
    size_t desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);

    // Allocate space for the descriptor
    desc = kmalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        printk(KERN_ERR "Failed to allocate shash_desc\n");
        ret = -ENOMEM;
        goto free_tfm;
    }

    // Initialize the descriptor
    desc->tfm = tfm;
    //desc->flags = 0;

    // Calculate the hash
    ret = crypto_shash_digest(desc, message, strlen(message), digest);
    if (ret) {
        printk(KERN_ERR "Failed to calculate hash\n");
        goto free_desc;
    }

    // Print the hash
    printk("Digital Signature (SHA-256):\n");
    printk("0x ");
    for (int i = 0; i < SIGNATURE_SIZE; i++) {
        printk(KERN_CONT"%02x ", digest[i]);
    }
    printk("\n");

free_desc:
    kfree(desc);
free_tfm:
    crypto_free_shash(tfm);
    return ret;
}

static void __exit digital_signature_exit(void)
{
    printk(KERN_INFO "Digital Signature module unloaded\n");
}

module_init(digital_signature_init);
module_exit(digital_signature_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Simple Digital Signature Kernel Module");

