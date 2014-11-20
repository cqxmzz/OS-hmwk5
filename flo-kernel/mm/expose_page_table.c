#include <linux/cred.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/syscalls.h>
#include <linux/init_task.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/io.h>

/* Map a target process's page table into address space of the current process.
 *
 * After successfully completing this call, addr will contain the 
 * page tables of the target process. To make it efficient for referencing 
 * the re-mapped page tables in user space, your syscall is asked to build a 
 * fake pgd table. The fake pgd will be indexed by pgd_index(va) (i.e. index 
 * for page directory for a given virtual address va). 
 *
 * @pid: pid of the target process you want to investigate, if pid == -1, 
 * you should dump the current process's page tables
 * @fake_pgd: base address of the fake pgd table
 * @addr: base address in the user space that the page tables should map to
 */

SYSCALL_DEFINE3(expose_page_table, pid_t __user, pid,
				unsigned long __user, fake_pgd,
				unsigned long __user, addr)
{
	return 0;
}
