#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

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

SYMBOL_CRC(work_run, 0x4b5a04e9, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcd24b256, "crypto_skcipher_encrypt" },
	{ 0x37a0cba, "kfree" },
	{ 0xc7f2fe14, "pcpu_hot" },
	{ 0x43babd19, "sg_init_one" },
	{ 0x802ef4e0, "crypto_skcipher_setkey" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x3fae7a0b, "crypto_destroy_tfm" },
	{ 0x122c3a7e, "_printk" },
	{ 0xa19b956, "__stack_chk_fail" },
	{ 0xf56d94f0, "crypto_skcipher_decrypt" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0x6d804f3a, "crypto_shash_digest" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x41ed3709, "get_random_bytes" },
	{ 0xd07ae855, "kmalloc_trace" },
	{ 0xc32ca0d9, "crypto_alloc_shash" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x86892d74, "kmalloc_caches" },
	{ 0xba754082, "v2p" },
	{ 0x10acbb21, "crypto_alloc_skcipher" },
	{ 0x453e7dc, "module_layout" },
};

MODULE_INFO(depends, "limit1");


MODULE_INFO(srcversion, "253FDA7FF227D203714B39D");
