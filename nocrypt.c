
#define pr_fmt(fmt) "nocrypt: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <asm/signal.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>

MODULE_DESCRIPTION("Detect and kill ransomware");
MODULE_AUTHOR("niveb");
MODULE_LICENSE("GPL");

unsigned int max_rename = 12;
module_param(max_rename, int, 0);
bool behaviour_detection = false;
module_param(behaviour_detection, bool, 0);

unsigned int rename_count = 0;
unsigned int target_pid = 0;
//Add here your custom extensions to block
#define BLACKLIST_SIZE 7
char *blacklist_ext[] = {"Clop","iFire","conti","monti","PUUUK", "Cheers","lockbit"};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

/* Send SIGKILL to the input task */
static bool kill_task(struct task_struct *task) {
	int signum = SIGKILL;
	struct kernel_siginfo info;
	memset(&info, 0, sizeof(struct kernel_siginfo));
	info.si_signo = signum;
	int ret = send_sig_info(signum, &info, task);
	if (ret < 0)
	{
		printk(KERN_INFO "error sending signal to %d\n", target_pid);
		return -1;
	}
	else 
	{
		printk(KERN_INFO "Target pid %d has been killed\n", target_pid);
		return 0;
	}
}

/* Check if the renaming operation is linked to a ransomware behaviour or not.
 * Returns true if the operation is allowed
 * Kill the process and returns false if the operation is not allowed
 */
static bool check_rename(char *oldname, char *newname) {
	struct task_struct *task;
	task = current;
	// we use parent pid because the tasks can be threads
	if (target_pid == task->real_parent->pid) {
		rename_count++;
	} else {
		target_pid = task->real_parent->pid;
		rename_count = 0;
	}
	//Check for specific known extensions
	//Find null terminating char
	int index = 0;
	int point_index = 0;
	int nmax = 200;
	//loop max nmax times
	for (index = 0; index < nmax; index++) {
		if (newname[index] == 0)
			break;
		else if (newname[index] == '.') {
			point_index = index;
		}
	}
	if ((point_index > 0) && (index < nmax)) {
		char *extension = newname+point_index+1;
		for (int i = 0; i < BLACKLIST_SIZE; i++) {
			if (strcmp(extension,blacklist_ext[i]) == 0) {
				pr_info("%s ransomware detected (renaming %s to %s)\n", extension, oldname, newname);
				kill_task(task);
				return false;
			}
		}
	}

	//Behaviour check
	if (behaviour_detection) {
		// if the same process pid is renaming more than n files, kill it
		if (rename_count >= max_rename) {
			pr_info("process %d detected as possible ransomware, renaming too much files (e.g. %s to %s)\n", target_pid, oldname, newname);
			kill_task(task);
			rename_count = 0;
			return false;
		}
	}
	return true;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_rename)(struct pt_regs *regs);

static asmlinkage long fh_sys_rename(struct pt_regs *regs)
{
	long ret = 0;
	char *oldname = (char*)regs->di;
	char *newname = (char*)regs->si;
	if (check_rename(oldname, newname)) {
		ret = real_sys_rename(regs);
	}

	return ret;
}
#else
static asmlinkage long (*real_sys_rename) (const char __user *oldname, const char __user *newname);

static asmlinkage long fh_sys_rename(const char __user *oldname, const char __user *newname)
{
	long ret = 0;
	if (check_rename(oldname, newname)) {
		ret = real_sys_rename(oldname, newname);
	}

	return ret;
}
#endif



/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_rename", fh_sys_rename, &real_sys_rename),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("nocrypt loaded (max_rename=%d,behaviour_detection=%d)\n",max_rename,behaviour_detection);

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	pr_info("nocrypt unloaded\n");
}
module_exit(fh_exit);
