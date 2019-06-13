#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include "khook/engine.c"
#define MAGIC_ID 11111
static struct nf_hook_ops my_nf_hook;
/*
#include <linux/fs.h> // has inode_permission() proto
KHOOK(inode_permission);
static int khook_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;
	ret = KHOOK_ORIGIN(inode_permission, inode, mask);
	printk("[fwmal]:%s(%p, %08x) = %d\n", __func__, inode, mask, ret);
	return ret;
}

#include <linux/binfmts.h> // has no load_elf_binary() proto
KHOOK_EXT(int, load_elf_binary, struct linux_binprm *);
static int khook_load_elf_binary(struct linux_binprm *bprm)
{
	int ret = 0;
	ret = KHOOK_ORIGIN(load_elf_binary, bprm);
	printk("[fwmal]:%s(%p) = %d\n", __func__, bprm, ret);
	return ret;
}
*/
unsigned int packet_hook(const struct nf_hook_ops *ops,
				struct sk_buff *socket_buffer,
				const struct net_device *in,
				const struct net_device *out, 
				int (*okfn)(struct sk_buff *))
{
	//printk("[fwmal]:acctpt packet\n");
	struct iphdr iph;
	const struct iphdr *ip_header = skb_header_pointer(socket_buffer, 0, sizeof(iph), &iph);
	if (!ip_header)
		return NF_ACCEPT;
	if (!ip_header->protocol)
		return NF_ACCEPT;
	/*
	//发送的IP包的标志设定为特殊值
	if (htons(ip_header->id) != MAGIC_ID)
		return NF_ACCEPT;
	*/
	if (ip_header->protocol == IPPROTO_TCP) {
		printk("[fwmal]:accept tcp packet\n");
		
	}

	return NF_ACCEPT;
}

void init_nf(void)
{
	my_nf_hook.hook = (void *)packet_hook;
	my_nf_hook.pf = PF_INET;
	my_nf_hook.priority = NF_IP_PRI_FIRST;
	my_nf_hook.hooknum = NF_INET_PRE_ROUTING;
	nf_register_hook(&my_nf_hook);
}

static int __init fwmal_init(void)
{
	int ret = khook_init();
	//init_nf();
	if (ret != 0)
		goto out;
	printk("[fwmal]:Hello World\n");
out:
	return ret;
}

static void __exit fwmal_exit(void)
{
	printk(KERN_ALERT "[fwmal]:Goodbye World\n");
	khook_cleanup();
}

module_init(fwmal_init);
module_exit(fwmal_exit);
MODULE_LICENSE("GPL");
