#include<linux/init.h>
#include<linux/module.h>
#include<linux/string.h>
#include<linux/kernel.h>
#include<linux/export.h>
#include<linux/scatterlist.h>
#include<linux/crypto.h>
#include <linux/err.h>
#include<crypto/skcipher.h>
#include<asm/desc.h>
#include<linux/interrupt.h>
#include<asm/irq_vectors.h>
#include<asm/io.h>
MODULE_LICENSE("GPL");
extern unsigned long v2p(unsigned long vaddr,unsigned long t_pid);
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
static const unsigned char aes_key[AES_KEY_SIZE] = "0123456789abcdef";

#define DUMP_SIZE 4096
static unsigned char data_share[DUMP_SIZE];
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
    stack_change();
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
