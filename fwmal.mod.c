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

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x7377b0b2, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x2ecda6f9, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x121ee85c, __VMLINUX_SYMBOL_STR(kernel_sendmsg) },
	{ 0x1b6314fd, __VMLINUX_SYMBOL_STR(in_aton) },
	{ 0xdf566a59, __VMLINUX_SYMBOL_STR(__x86_indirect_thunk_r9) },
	{ 0xc051dec2, __VMLINUX_SYMBOL_STR(kallsyms_on_each_symbol) },
	{ 0xb679cb5a, __VMLINUX_SYMBOL_STR(sock_create_kern) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0x75607057, __VMLINUX_SYMBOL_STR(kthread_create_on_node) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xca86f1d3, __VMLINUX_SYMBOL_STR(vmap) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xc5fdef94, __VMLINUX_SYMBOL_STR(call_usermodehelper) },
	{ 0x79bb27a3, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x81a84515, __VMLINUX_SYMBOL_STR(stop_machine) },
	{ 0x4fafbb44, __VMLINUX_SYMBOL_STR(init_task) },
	{ 0x2ea2c95c, __VMLINUX_SYMBOL_STR(__x86_indirect_thunk_rax) },
	{ 0xa78b1427, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0xcc5005fe, __VMLINUX_SYMBOL_STR(msleep_interruptible) },
	{ 0x87b393c2, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xf38f23da, __VMLINUX_SYMBOL_STR(kernel_recvmsg) },
	{ 0x94961283, __VMLINUX_SYMBOL_STR(vunmap) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x71cc7e8f, __VMLINUX_SYMBOL_STR(vmalloc_to_page) },
	{ 0xe3fffae9, __VMLINUX_SYMBOL_STR(__x86_indirect_thunk_rbp) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "A9E7270B377822D9DB52912");
