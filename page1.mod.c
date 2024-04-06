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

KSYMTAB_FUNC(pgd_copy, "", "");

SYMBOL_CRC(pgd_copy, 0xb4d386fa, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xc9210694, "pcpu_hot" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x122c3a7e, "_printk" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x5c6fcbb3, "kmalloc_trace" },
	{ 0xab69f068, "kmalloc_caches" },
	{ 0x6ab589bc, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "864F8F31F4B4F8011886463");
