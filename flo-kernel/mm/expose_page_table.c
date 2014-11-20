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
	/* Qiming Chen */
	struct mm_struct *mm;
	struct vm_area_struct *user_vma = NULL;
	struct vm_area_struct *curr_vma;
	struct expose_pg_addrs *pg_addrs;
	struct task_struct *task;
	int errno;

	/* check valid */
	if (pid == NULL || addr == NULL || fake_pgd == NULL)
		return -EINVAL;

	/* self */
	if (pid == -1)
		task = current;
		mm = current->mm;
	else {
		task = find_task_by_vpid(pid);
		if (!task)
			return -EINVAL;
		mm = task->mm;
	}
	/* check mm exist */
	if (!mm)
		return -EINVAL;
	pg_addrs = kmalloc(sizeof(struct expose_pg_addrs), GFP_KERNEL);
	if (!pg_addrs)
		return -EFAULT;

	INIT_LIST_HEAD(&pg_addrs->list);
	pg_addrs->pid = pid;

	/* lock */
	down_read(&(mm->mmap_sem));

	/* check user address valid */
	user_vma = check_user_vma_is_valid(mm, (unsigned long)address);
	if (!user_vma) {
		kfree(pg_addrs);
		up_read(&(mm->mmap_sem));
		return -EINVAL;
	}
	pg_addrs->address = address;

	/* add the new pg_addrs to the list */
	if (mm->pg_addrs)
		list_add(&(pg_addrs->list), &(mm->pg_addrs->list));
	else
		mm->pg_addrs = pg_addrs;

	/* get the list of VMAs */
	curr_vma = mm->mmap;

	/* go through the list of VMAs and copy the PTEs */
	do {
		errno = copy_ptes_from_vma(mm, curr_vma, user_vma, address);
		if (errno < 0){
			/*
			if (mm->pg_addrs == pg_addrs)
				mm->pg_addrs == NULL;
			else
				list_remove(pg_addrs->list);
			kfree(pg_addrs);
			*/
			up_read(&(mm->mmap_sem));
			return errno;
		}
		curr_vma = curr_vma->vm_next;
	} while (curr_vma);

	/* unlock */
	up_read(&(mm->mmap_sem));

	return 0;
}
