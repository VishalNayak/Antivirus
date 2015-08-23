#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/prctl.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fcntl.h>

MODULE_LICENSE("GPL");

#define SYS_CALL_TABLE_ADDRESS 0xc1697140 
#define TTOP	"/home/kbandi/netsec/Antivirus"

void set_page_rw(long unsigned int _addr);
void **sys_call_table;

asmlinkage int fake_sys_open(const char *file, int flags, int mode);

asmlinkage int (*original_sys_execve)(const char*, char *const argv[], char *const envp[]);
asmlinkage int (*original_sys_open) (const char *, int, int);
asmlinkage int (*original_sys_read) (int, void *, size_t);
asmlinkage int (*original_sys_close) (int);
asmlinkage int (*original_sys_prctl) (int option, char *arg2,
	unsigned long arg3, unsigned long arg4,
	unsigned long arg5);
asmlinkage char* (*original_sys_getcwd)(char *, size_t);
asmlinkage int (*original_sys_stat)(const char*, struct stat *);

static int scanning = 0;
mm_segment_t oldfs;

int user_proc_init(struct subprocess_info *info, struct cred *new)
{
	scanning = 1;
//	printk(KERN_NOTICE "SBU-Antivirus user level program initiated:\n");
	return 0;
}

void user_proc_cleanup(struct subprocess_info *info)
{
	scanning = 0;
//	printk(KERN_EMERG "SBU-Antivirus user level program completed.\n");
	return;
}


static int user_space_scan(const char *file)
{
	struct subprocess_info *sub_info;
	char cwd[200];
	int i = 0;
	char **argv;
	static char *envp[] =
	{ "HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", "DISPLAY=:0", "TOP="TTOP,
		NULL };

	original_sys_getcwd(cwd, 100);

	if (file[0] != '/') {
		sprintf(cwd, "%s/%s", cwd, file);
	
	} else {
		sprintf(cwd, "%s", file);
	}

	argv = kmalloc(5 * sizeof(char *), GFP_KERNEL);
	if (!argv)
		return 0;

	for (i = 0; i < 4; i++) {
		argv[i] = kmalloc(200 * sizeof(char), GFP_KERNEL);
		if (!argv[i])
			return 0;
	}

	strcpy(argv[0], TTOP"/antivirus");
	strcpy(argv[1], "-scan");
	strcpy(argv[2], cwd);
	argv[3] = NULL;
	
/*	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC); //sub_info, UMH_WAIT_PROC);
*/
	sub_info =
		call_usermodehelper_setup(argv[0], argv, envp, GFP_ATOMIC,
				user_proc_init, user_proc_cleanup, NULL);
	if (sub_info == NULL)
		return -ENOMEM;
	if (!scanning){
		call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
	}

//	kfree(argv[0]);
//	kfree(argv[1]);
//	kfree(argv[2]);
	return 0;
}

char th_name[17] = { 0 };

asmlinkage int our_fake_execve_function(const char* file, char *const argv[], char *const env[])
{

	int ret;
	int fd;
	struct stat log_file_stat;
	char *log_file_content;
	char search_for[200];
	char cwd[201];
	char *found;

	printk("Checking exec %s\n", file);

 	oldfs = get_fs();
	set_fs(KERNEL_DS);

	original_sys_getcwd(cwd, 100);

	if (!(strlen(file) > 0)) {
		goto execitnow;
	}

	if (file[0] != '/') {
		sprintf(cwd, "%s/%s", cwd, file);

	} else {
		sprintf(cwd, "%s", file);
	}

	sprintf(search_for, "[%s]Virus Found!", cwd);

	user_space_scan(file);

	fd = original_sys_open("/tmp/antivirus.log", O_RDONLY | O_CREAT, 0);
	if (fd < 0) {
		printk(KERN_EMERG "Failed to open log file");
		goto execitnow;
	}

	ret = original_sys_stat("/tmp/antivirus.log", &log_file_stat);
	if (ret < 0) {
		printk(KERN_EMERG "Failed to stat log file");
		goto execitnow;
	}
	
	log_file_content = kmalloc(log_file_stat.st_size * sizeof(char), GFP_KERNEL);
	if (!log_file_content) {
		printk(KERN_EMERG "Failed to alloc memory of size\n");
		goto execitnow;
	}

	original_sys_read(fd, log_file_content, log_file_stat.st_size);

	log_file_content[log_file_stat.st_size - 1] = '\0';

	found = strstr(log_file_content, search_for);
	if (found) {
		printk("Virus found in %s\n", file);
		goto fail;
	}

	original_sys_close(fd);

	fd = original_sys_open("/tmp/antivirus.log", O_TRUNC | O_RDWR, 0);
	if (fd < 0) {
		printk("failed to open to truncate\n");
		goto execitnow;
	}
	original_sys_close(fd);
	
	set_fs(oldfs);

execitnow:
	return original_sys_execve(file, argv, env);
fail:
	return -1;
}

void set_page_rw(long unsigned int _addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(_addr, &level);
	if (pte->pte & ~_PAGE_RW)
		pte->pte |= _PAGE_RW;
}

static int __init mod_entry_func(void)
{
	sys_call_table = (void *)SYS_CALL_TABLE_ADDRESS;
	set_page_rw(SYS_CALL_TABLE_ADDRESS);

	original_sys_open = sys_call_table[__NR_open];
	original_sys_read = sys_call_table[__NR_read];
	original_sys_close = sys_call_table[__NR_close];
	original_sys_prctl = sys_call_table[__NR_prctl];
        original_sys_execve = sys_call_table[__NR_execve];
        original_sys_getcwd = sys_call_table[__NR_getcwd];
        original_sys_stat = sys_call_table[__NR_stat];

        sys_call_table[__NR_execve] = our_fake_execve_function;

	return 0;
}

static void __exit mod_exit_func(void)
{
        sys_call_table[__NR_execve] = original_sys_execve;
}

module_init(mod_entry_func);
module_exit(mod_exit_func);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netcop@cs.stonybrook.edu>");
MODULE_DESCRIPTION("Our kernel antivirus");
