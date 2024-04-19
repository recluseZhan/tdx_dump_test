#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

KSYMTAB_FUNC(work_run, "", "");

SYMBOL_CRC(work_run, 0x4b5a04e9, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xdbecd794, "crypto_skcipher_encrypt" },
	{ 0xa2f2ed94, "filp_open" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x608741b5, "__init_swait_queue_head" },
	{ 0x69acdf38, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0xc9210694, "pcpu_hot" },
	{ 0x43babd19, "sg_init_one" },
	{ 0x52c9affc, "crypto_skcipher_setkey" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xe5b491a5, "crypto_destroy_tfm" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x122c3a7e, "_printk" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x482499a7, "crypto_skcipher_decrypt" },
	{ 0xa916b694, "strnlen" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0xd59ada92, "crypto_shash_digest" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0x7bd9995f, "crypto_alloc_akcipher" },
	{ 0x25974000, "wait_for_completion" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x1737cbea, "filp_close" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0x5c6fcbb3, "kmalloc_trace" },
	{ 0x754d539c, "strlen" },
	{ 0x2c759500, "crypto_alloc_shash" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xab69f068, "kmalloc_caches" },
	{ 0xb248d97, "kernel_write" },
	{ 0xba754082, "v2p" },
	{ 0x96e77414, "crypto_alloc_skcipher" },
	{ 0x6ab589bc, "module_layout" },
};

MODULE_INFO(depends, "limit1");


MODULE_INFO(srcversion, "B298B753ED499F8A818CA23");
