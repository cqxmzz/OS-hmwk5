#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

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
	struct mm_struct *mm;
	if (pid == -1)
		pid = current->pid;
	mm = current->mm;
	/* If this task_struct is a thread, just return.
	 * Wendan Kang
	 */
	if (mm == NULL)
		return -EINVAL;
	return 0;
}
