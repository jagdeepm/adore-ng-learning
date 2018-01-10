#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xb6aa582b, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x4bbb582b, __VMLINUX_SYMBOL_STR(skb_dequeue) },
	{ 0x2be0808c, __VMLINUX_SYMBOL_STR(pid_vnr) },
	{ 0x433b3c5e, __VMLINUX_SYMBOL_STR(skb_recv_datagram) },
	{ 0x6c2e3320, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x5ab47c3d, __VMLINUX_SYMBOL_STR(PDE_DATA) },
	{ 0xf087137d, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x4dc514c7, __VMLINUX_SYMBOL_STR(kobject_put) },
	{ 0x5bdb88fb, __VMLINUX_SYMBOL_STR(kobject_del) },
	{ 0x6f13ceff, __VMLINUX_SYMBOL_STR(kobject_uevent) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{        0, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0xf1920828, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0xd7ada38c, __VMLINUX_SYMBOL_STR(dput) },
	{ 0xc5f6ce64, __VMLINUX_SYMBOL_STR(iput) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x2e60bace, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x68e2f221, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0x67f7403e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x8134dd16, __VMLINUX_SYMBOL_STR(init_task) },
	{ 0x13ea2055, __VMLINUX_SYMBOL_STR(d_lookup) },
	{ 0x6f20960a, __VMLINUX_SYMBOL_STR(full_name_hash) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbb9dc52, __VMLINUX_SYMBOL_STR(d_alloc) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x751a865e, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "8D720C32AF48EF09E073CA0");
