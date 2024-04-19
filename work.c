#include<linux/init.h>
#include<linux/module.h>
#include<linux/string.h>
#include<linux/kernel.h>
#include<linux/export.h>
#include<linux/scatterlist.h>
#include<linux/crypto.h>
#include <crypto/sha256_base.h>
#include <linux/err.h>
#include<crypto/skcipher.h>
#include<asm/desc.h>
#include<linux/interrupt.h>
#include<asm/irq_vectors.h>
#include<asm/io.h>


#include <linux/gfp.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <crypto/akcipher.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
unsigned long urdtsc(void)
{
    unsigned int lo,hi;

    __asm__ __volatile__
    (
        "rdtsc":"=a"(lo),"=d"(hi)
    );
    return (unsigned long)hi<<32|lo;
}
extern unsigned long v2p(unsigned long vaddr,unsigned long t_pid);
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
static const unsigned char aes_key[AES_KEY_SIZE] = "0123456789abcdef";

#define DUMP_SIZE 4096
static unsigned char data_share[DUMP_SIZE];

#define SIGNATURE_SIZE 32 // Size of SHA-256 hash in bytes
//static char *message = "hello"; // Message to be signed
//#define DATA_SIZE (1ULL<<20)
#define DATA_SIZE 4096
unsigned long t_sha,t_rsa;
char buf_sha[20],buf_rsa[20];
int digital_signature(void)
{
    uint8_t *message;
    message = kmalloc(DATA_SIZE,GFP_KERNEL);
    get_random_bytes(message,DATA_SIZE);
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    uint8_t digest[SIGNATURE_SIZE];
    int ret = 0;
    unsigned long t1,t2,t;
    struct file *fp;
    loff_t pos = 0;
    
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
    /*
    for(int i=0;i<DATA_SIZE;i++){
        clflush(&message[i]);
    }
    for(int i=0;i<SIGNATURE_SIZE;i++){
        clflush(&digest[i]);
    }
    for(int i=0;i<desc_size;i++){
        clflush(&desc[i]);
    }*/
    // Calculate the hash
    
    t1=urdtsc();
    ret = crypto_shash_digest(desc, message, DATA_SIZE, digest);
    t2=urdtsc();
    t_sha = t2 - t1;
    printk("sha256 time(ns) : %ld \n ", (t2-t1));
    snprintf(buf_sha,sizeof(buf_sha),"%lu",t_sha);
    fp  = filp_open("./flag_sha.txt", O_RDWR|O_APPEND|O_CREAT ,0644);
    kernel_write(fp, buf_sha, strlen(buf_sha), &pos);
    kernel_write(fp, "\n", 1, &pos);
    filp_close(fp, NULL);
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
// RSA
const char *priv_key =
    "\x30\x82\x02\x5d\x02\x01\x00\x02\x81\x81\x00\xd0"
    "\xb4\x5a\xc1\x9e\x2e\x4d\xae\xbd\x51\x39\xcc\x4b"
    "\x12\xf5\x76\x30\xcf\x39\x97\xf1\xd3\x0d\xaa\x37"
    "\x70\x2d\x2f\x01\xc9\x69\x09\xe3\x4e\xd5\x90\x68"
    "\xfe\xbf\x7c\x8b\x86\xdf\xf3\x14\xb3\x96\xcf\x1b"
    "\x39\xe3\xe6\x8a\x77\x6d\xe4\x89\xef\xdb\xba\x4a"
    "\x40\x6d\xa9\xec\x21\x62\x00\xa4\xc3\x45\xcc\xdd"
    "\x56\xb2\x77\x59\x46\x17\x27\x0e\x2c\xfe\x85\x53"
    "\x72\x26\x9b\xdc\x24\x83\xd1\x67\xa7\x4c\x88\x70"
    "\x78\x3f\x1c\x60\xd4\x95\x14\x57\xfc\xdb\x15\xaa"
    "\xab\x31\x32\xb2\x44\x72\xdd\xb0\x0b\x13\x62\x03"
    "\x50\x1d\xd4\x6a\xf6\xb2\x23\x02\x03\x01\x00\x01"
    "\x02\x81\x80\x7b\x83\x10\xe6\xde\xf7\x26\x30\x10"
    "\x88\x3e\x7d\x61\xbc\xa1\x99\xc5\xbf\x0d\xa5\x97"
    "\x8e\xc0\xda\x88\x9e\x91\x8e\xed\x2e\xc6\x43\xfc"
    "\xcb\x0d\xe6\xbd\xcc\x6d\x84\x86\x8a\x56\x84\xe4"
    "\x2e\x78\x44\xaf\x27\x2e\x71\xa4\x66\x93\x99\x99"
    "\xec\x62\x8c\x38\x1f\x33\x06\x37\xc1\x9d\x17\x6b"
    "\xad\xfb\x8e\x44\xd3\x11\xcb\x74\xa4\x01\x78\xb0"
    "\x9c\x64\xd3\x0d\x63\x99\x65\xe3\xca\xae\x11\xb2"
    "\xc4\x00\x36\xc2\xfc\x4b\x7b\x6f\x9e\x84\xb6\x97"
    "\x00\x56\x5b\x09\xa1\x28\xf5\x28\x8d\xc7\x93\x45"
    "\xba\xc0\x6b\xa9\x2d\xeb\x02\xcd\xde\x1e\x29\x02"
    "\x41\x00\xf6\x0e\x41\xbc\xfa\x40\x82\xba\xa0\x6a"
    "\xa5\x75\x5c\xcd\xfe\xa8\x11\xa6\xef\xbc\xad\x5f"
    "\x86\x40\xb4\x5a\x65\xc1\x7b\x5e\x89\xc2\x60\x38"
    "\x0e\x8b\x7d\x7d\x99\x30\x01\xf1\xea\x1e\x3e\x46"
    "\xf4\xd2\xd9\x80\xaf\x3a\x4b\x2f\xbb\x91\xbb\xb7"
    "\x22\x2d\x6a\x0f\x4e\x6f\x02\x41\x00\xd9\x23\xa7"
    "\x98\x0c\x58\xe1\x5d\xa7\x15\x05\xc6\xd9\x7b\xc5"
    "\x7b\xd3\x01\x8b\x1e\xf1\x2e\x99\xc5\xac\x41\xf1"
    "\x92\x88\xd9\x8e\x50\x86\xf9\x2f\x66\x42\xeb\xf9"
    "\x80\x78\xfa\xc7\xea\x63\x35\x7e\x6f\xc5\x35\x36"
    "\x6b\xa1\x8a\xa3\x49\x97\xbc\xa6\x9b\x5c\x6e\xf1"
    "\x8d\x02\x40\x44\x70\xa0\xbe\x64\xc9\x4e\xd3\x84"
    "\x4d\x45\xaa\x88\x5e\xcf\xe7\x85\xc9\x6e\x43\x87"
    "\xe1\xdb\x20\xe2\x49\x86\xa6\x33\x9f\x8f\x27\xde"
    "\xc5\x98\xde\x19\xd0\xb6\xac\x50\xce\x2e\x35\xad"
    "\x52\xe5\x44\x44\xb5\x73\x87\xfe\x63\xcf\x83\x70"
    "\xb8\x36\xac\x75\x24\xbe\xc7\x02\x41\x00\x87\xd2"
    "\x97\xa8\xb2\x40\x7e\x67\xf8\x75\x5b\xf1\xb0\x64"
    "\x8d\x79\x10\xd9\xec\x4d\xe4\x8b\x43\xc0\xb4\x29"
    "\x63\x94\x47\x69\xde\x6d\x5c\xa0\x4e\x17\xe7\x50"
    "\x77\xf6\xf6\xb5\xd7\x8b\x33\x97\x68\x89\x3d\x90"
    "\x35\x84\x49\xbd\xd0\xb9\xdd\xe2\x31\x4d\x09\x1a"
    "\x94\x99\x02\x41\x00\xc9\x12\xec\x64\xe9\x01\x27"
    "\x10\x6c\xad\xc5\x83\x8a\x26\x39\xe0\x05\xde\xde"
    "\xf9\x1a\x5d\xf6\xcb\xe8\xd2\x9b\x40\xd5\x11\xc8"
    "\x9a\x6d\x29\xb6\x15\x36\x9a\xee\x45\xe2\x51\x14"
    "\xa8\x2d\xab\x57\x86\x80\x87\x0a\x02\xaf\xfa\xda"
    "\x5e\x7d\xfb\x84\xd1\x3a\xe0\xed\x57";
const int priv_key_len = 609;
 
const char *pub_key =
    "\x30\x81\x88\x02\x81\x80\x6D\x4D\xAF\xF5\x32\x98\xFA\x33\xF2\x4A"
    "\xB0\x50\x27\x6F\x50\x0B\x28\xCA\x5F\x6E\xDE\xEC\x7B\xAE\xEB\xD1"
    "\x89\xDF\xCF\x8D\x12\x6C\x0D\xF2\x32\x65\xB7\x04\xF2\xB8\x76\x67"
    "\xE9\x28\xC3\x12\x6B\x4A\x52\x09\xD6\x61\x9B\x21\x25\x04\xE0\x9A"
    "\xEC\xBC\x25\x3F\xFC\x6F\x1A\x98\xA8\x02\xA8\x2E\x89\x91\x20\xCF"
    "\xF0\xD1\x9D\x09\x35\xAC\x95\xE2\xE4\x8E\x5B\x7C\x34\x93\x39\x4F"
    "\x33\xBD\x6E\xE7\xC5\xBB\x2A\x28\x32\x13\x62\x39\x37\x87\x40\xE7"
    "\x59\xF8\x94\xAD\xC4\x2E\xAF\x23\xF4\x98\xCD\x90\x27\x96\x41\xC6"
    "\x4A\xCD\x6D\x56\xFD\x5B\x02\x03\x01\x00\x01";
const int pub_key_len = 139;
 
char *crypted = NULL;
int crypted_len = 0;
 
struct tcrypt_result {
    struct completion completion;
    int err;
};
static inline  void hexdump(unsigned char *buf,unsigned int len) {
    while(len--)
        printk(KERN_CONT "%02x",*buf++);
    printk("\n");
}
 
static void tcrypt_complete(struct crypto_async_request *req, int err)
{
    struct tcrypt_result *res = req->data;
 
    if (err == -EINPROGRESS)
        return;
 
    res->err = err;
    complete(&res->completion);
}
 
static int wait_async_op(struct tcrypt_result *tr, int ret)
{
    if (ret == -EINPROGRESS || ret == -EBUSY) {
        wait_for_completion(&tr->completion);
        reinit_completion(&tr->completion);
        ret = tr->err;
    }
    return ret;
}
 
static int uf_akcrypto(struct crypto_akcipher *tfm,
                         void *data, int datalen, int phase)
{
    void *xbuf = NULL;
    struct akcipher_request *req;
    void *outbuf = NULL;
    struct tcrypt_result result;
    unsigned int out_len_max = 0;
    struct scatterlist src, dst;
    //int pub_key_len = strlen(pub_key);
   // int priv_key_len = strlen(priv_key);
    //priv_key_len=609;
    //printk("pub:%d\n",pub_key_len);
    int err = -ENOMEM;
    xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!xbuf)
         return err;
 
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req)
         goto free_xbuf;
 
    init_completion(&result.completion);
 
    if (!phase){  //test
         err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
    }else{
         err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
    }
//  err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
    if (err){
        printk("set key error! %d,,,,,%d\n", err,phase);
        goto free_req;
    }
 
    err = -ENOMEM;
    out_len_max = crypto_akcipher_maxsize(tfm);
    outbuf = kzalloc(out_len_max, GFP_KERNEL);
    if (!outbuf)
         goto free_req;
 
    if (WARN_ON(datalen > PAGE_SIZE))
         goto free_all;
 
    memcpy(xbuf, data, datalen);
    sg_init_one(&src, xbuf, datalen);
    sg_init_one(&dst, outbuf, out_len_max);
    
    
    akcipher_request_set_crypt(req, &src, &dst, datalen, out_len_max);
    //akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,tcrypt_complete, &result);
    
    unsigned long t1,t2;
    int en_ret,de_ret;
    struct file *fp;
    loff_t pos = 0;
    
    if (phase){
        t1=urdtsc();
        en_ret=crypto_akcipher_encrypt(req);
        t2=urdtsc();
        t_rsa = t2 - t1;
        printk("rsa time(ns) : %ld \n ", (t2-t1));
        snprintf(buf_rsa,sizeof(buf_rsa),"%lu",t_rsa);
        fp  = filp_open("./flag_rsa.txt", O_RDWR|O_APPEND|O_CREAT ,0644);
        kernel_write(fp, buf_rsa, strlen(buf_rsa), &pos);
        kernel_write(fp, "\n", 1, &pos);
        filp_close(fp, NULL);
        
        
        err = wait_async_op(&result, en_ret);
        if (err) {
            pr_err("alg: akcipher: encrypt test failed. err %d\n", err);
            goto free_all;
        }
        memcpy(crypted,outbuf,out_len_max);
        crypted_len = out_len_max;
        hexdump(crypted, out_len_max);
    }else{
        //t1=urdtsc();
        de_ret = crypto_akcipher_decrypt(req);   
        //t2=urdtsc();
        //printk("verif time(ns) : %ld \n ", (t2-t1));
        err = wait_async_op(&result, de_ret);
        if (err) {
            pr_err("alg: akcipher: decrypt test failed. err %d\n", err);
            goto free_all;
        }
        hexdump(outbuf, out_len_max);
    }
 
free_all:
    kfree(outbuf);
free_req:
    akcipher_request_free(req);
free_xbuf:
    kfree(xbuf);
    return err;
}
 
 
static int userfaultfd_akcrypto(void *data, int datalen, int phase)
{
     struct crypto_akcipher *tfm;
     int err = 0;
 
     tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = uf_akcrypto(tfm,data,datalen,phase);
 
     crypto_free_akcipher(tfm);
     return err;
}
#define DATA_SIZE 33
int test_rsa(void)
{  
    crypted = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!crypted){
        printk("crypted kmalloc error\n");
        return -1;
    }
    //const char *msg = "\x54\x85\x9b\x34\x2c\x49\xea\x2a\x54\x85\x9b\x34\x2c\x49\xea\x2a\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    char msg[DATA_SIZE];
    memset(msg,'a',DATA_SIZE);
    msg[DATA_SIZE-1]='\0';

    int msg_len = strlen(msg);
    userfaultfd_akcrypto(msg,msg_len,1);
    //userfaultfd_akcrypto(crypted,crypted_len,0);
    kfree(crypted);
    return 0;
}

//
static int aes_encrypt(const unsigned char *input, unsigned char *output){
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_src, sg_dst;
    int ret;
    // allocate context
    tfm = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
    if(IS_ERR(tfm)){
        printk(KERN_ERR"Error allocating cipher\n");
        return PTR_ERR(tfm);
    }
    // init req
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if(!req){
        printk(KERN_ERR"Error allocating request\n");
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }
    // set key
    ret = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_SIZE);
    if(ret){
        printk(KERN_ERR"Error setting key\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // prepare input and output scatterlist
    sg_init_one(&sg_src, input, AES_BLOCK_SIZE);
    sg_init_one(&sg_dst, output, AES_BLOCK_SIZE);
    // init req
    skcipher_request_set_crypt(req, &sg_src, &sg_dst, AES_BLOCK_SIZE, NULL);    
    // encrypt
    ret = crypto_skcipher_encrypt(req);
    if(ret){
        printk(KERN_ERR"Encryption failed\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // free
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return ret;
}
static int aes_decrypt(const unsigned char *input, unsigned char *output){
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_src, sg_dst;
    int ret;
    // allocate context
    tfm = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
    if(IS_ERR(tfm)){
        printk(KERN_ERR"Error allocating cipher\n");
        return PTR_ERR(tfm);
    }
    // init req
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if(!req){
        printk(KERN_ERR"Error allocating request\n");
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }
    // set key
    ret = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_SIZE);
    if(ret){
        printk(KERN_ERR"Error setting key\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // prepare input and output scatterlist
    sg_init_one(&sg_src, input, AES_BLOCK_SIZE);
    sg_init_one(&sg_dst, output, AES_BLOCK_SIZE);
    // init req
    skcipher_request_set_crypt(req, &sg_src, &sg_dst, AES_BLOCK_SIZE, NULL);    
    // decrypt
    ret = crypto_skcipher_decrypt(req);
    if(ret){
        printk(KERN_ERR"Decryption failed\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // free
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return ret;
}
void work_encrypt(const unsigned char *input, unsigned char *output){
    for(int i = 0; i < DUMP_SIZE / AES_BLOCK_SIZE; i++){
        aes_encrypt(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE);
    }
}
void work_decrypt(const unsigned char *input, unsigned char *output){
    for(int i = 0; i < DUMP_SIZE / AES_BLOCK_SIZE; i++){
        aes_decrypt(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE);
    }
}

void work_dump(unsigned char *data_crypto){
    unsigned long opcode = 0x10001;
    unsigned long gpa = v2p(data_crypto,(unsigned long)current->pid);
    unsigned long ret;
    printk("gpa=%lx\n",gpa);
    /*
    asm(
        "movq %1,%%r11;\n\t"
        "movq %2,%%r12;\n\t"
        "movq %3,%%r13;\n\t"
        "tdcall;\n\t"
        "movq %%r10,%0;\n\t"
        :"=r"(ret)
        :"r"(opcode),"r"(gpa),"r"(DUMP_SIZE):
    );
    printk("ret=%lx\n",ret);
    */
}

void work_map(void){
    unsigned char data_crypto[DUMP_SIZE];
    unsigned char data_page[DUMP_SIZE]="hello,world!thiswork";
    //unsigned char data_d[DUMP_SIZE];
    work_encrypt(data_page,data_crypto);
    printk("en:");
    for(int i = 0; i < DUMP_SIZE; i++)
        printk(KERN_CONT"%02x ",data_crypto[i]);
    //trampoline((unsigned long)current->pid,(unsigned long)data_crypto,1);
    work_dump(data_crypto);
    
}

gate_desc old_idt_table[256];
void get_old_idt_table(void) {
    struct desc_ptr idtr;
    store_idt(&idtr);
    memcpy(old_idt_table, (void *)idtr.address, sizeof(old_idt_table));
}
gate_desc new_idt_table[256];
void init_new_idt_table(void) {
    memcpy(new_idt_table, old_idt_table, sizeof(new_idt_table));
    /*for (int i = 0; i < 256; ++i) {
        new_idt_table[i].bits.type = GATE_INTERRUPT;
        new_idt_table[i].offset_low = 0;
        new_idt_table[i].segment = 0;
        new_idt_table[i].offset_middle = 0;
        #ifdef CONFIG_X86_64
        new_idt_table[i].offset_high = 0;
        new_idt_table[i].reserved = 0;
        #endif
    }*/
}
void idt_change(void) {
    struct desc_ptr idtr;
    get_old_idt_table();
    init_new_idt_table();
    idtr.address=(unsigned long)new_idt_table;
    idtr.size=sizeof(new_idt_table);
    //load_idt(&idtr);
}
void disable_int(void)
{
    asm volatile("cli\n\t":::);
    outb(inb(0x70)|0x80,0x70);
}
void start_int(void)
{
    asm volatile("sti\n\t":::);
    outb(inb(0x70)&0x70,0x70);
}
//
#define PGD_SIZE (sizeof(pgd_t) * PTRS_PER_PGD)
#define NEW_STACK_SIZE 8192
void page_change(void){
    struct task_struct *task=current;
    pgd_t *old_pgd,*new_pgd;
    phys_addr_t in_cr3;
    old_pgd = task->mm->pgd;
    new_pgd = kmalloc(PGD_SIZE,GFP_KERNEL);
    memcpy(new_pgd,old_pgd,PGD_SIZE);
    in_cr3 = virt_to_phys(new_pgd);
    asm volatile(
        "movq %0,%%cr3\n\t"
        ::"r"(in_cr3):
    );
}
void new_func(void *new_stack){
    work_map();
}
void stack_change(void){
    uint8_t *new_stack;
    new_stack = kmalloc(NEW_STACK_SIZE, GFP_KERNEL);
    asm volatile(
        "movq %0,%%rsp\n\t"
        "sub $8,%%rsp\n\t"
        "call new_func\n\t"
        ::"r"(new_stack+NEW_STACK_SIZE):
    );
}

void work_run(void){
    disable_int();
    start_int();
    page_change();
    //stack_change();
    digital_signature();
    test_rsa();
}

static int __init work_init(void)
{
    printk(KERN_ALERT"work module is entering..\n");
    return 0;
}

static void __exit work_exit(void)
{
    printk(KERN_ALERT"work module is leaving..\n");
    
}
EXPORT_SYMBOL(work_run);

module_init(work_init);
module_exit(work_exit);
