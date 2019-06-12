#include <linux/kernel.h>
#include <linux/module.h>

#include "khook/engine.c"

#include <linux/fs.h> // has inode_permission() proto
KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask)
{
        int ret = 0;
        ret = KHOOK_ORIGIN(inode_permission, inode, mask);
        printk("%s(%p, %08x) = %d\n", __func__, inode, mask, ret);
        return ret;
}

#include <linux/binfmts.h> // has no load_elf_binary() proto
KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
        int ret = 0;
        ret = KHOOK_ORIGIN(load_elf_binary, bprm);
        printk("%s(%p) = %d\n", __func__, bprm, ret);
        return ret;
}

static int __init fwmal_init(void)
{
	int ret = khook_init();
	if (ret != 0)
		goto out;
	printk("Hello World\n");
out:
	return ret;
}

static void __exit fwmal_exit(void)
{
	printk(KERN_ALERT "Goodbye World\n");
	khook_cleanup();
}

module_init(fwmal_init);
module_exit(fwmal_exit);
MODULE_LICENSE("GPL");
