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

SYMBOL_CRC(work_map, 0x2bb34e48, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcd24b256, "crypto_skcipher_encrypt" },
	{ 0xc7f2fe14, "pcpu_hot" },
	{ 0x43babd19, "sg_init_one" },
	{ 0x802ef4e0, "crypto_skcipher_setkey" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x3fae7a0b, "crypto_destroy_tfm" },
	{ 0x122c3a7e, "_printk" },
	{ 0xa19b956, "__stack_chk_fail" },
	{ 0xf56d94f0, "crypto_skcipher_decrypt" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xd0760fc0, "kfree_sensitive" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xba754082, "v2p" },
	{ 0x10acbb21, "crypto_alloc_skcipher" },
	{ 0x453e7dc, "module_layout" },
};

MODULE_INFO(depends, "limit1");


MODULE_INFO(srcversion, "2AD9AE867A6086E1086E694");
