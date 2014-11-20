#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>



static int copy_ptes(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *user_vma, void *user_addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;

	pgd = pgd_offset(mm, addr);

	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;

		pud = pud_offset(pgd, addr);
		if (pud_none_or_clear_bad(pud))
			continue;

		pmd = pmd_offset(pud, addr);
		if (pmd_none_or_clear_bad(pmd))
			continue;

		pte = pte_offset_map(pmd, addr);

		err = copy_pte_to_user(pte, mm, addr, user_addr);
		if (err < 0)
			return err;
	} while (pgd++, addr = next, addr != end);
}

static struct vm_area_struct * check_user_vma_is_valid(struct mm_struct *mm,
	unsigned long address)
{
	struct list_head *pglist;
	struct vm_area_struct *vma, *cur_vma;
	unsigned long page_table_size =
			PAGE_SIZE * PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD;
	struct expose_pg_addrs *epga;
	struct task_struct *p;
	struct task_struct *task;
	struct list_head *pos;
	struct mm_struct *taskmm;

	vma = find_vma(mm, address);
	if (vma == NULL)
		return NULL;
	/* Check the size is large enough */
	if ((vma->vm_end - address) < page_table_size)
		return NULL;

	/* Check address does not belong to another address' vma*/
	p=&init_task;
	list_for_each(pos, &p->tasks) {
		task = list_entry(pos, struct task_struct, tasks);
		taskmm = task->mm;
		if (taskmm->pg_addrs && taskmm->pg_addrs->pid == current->pid) {
			list_for_each(pglist, &taskmm->pg_addrs->list) {
				epga = list_entry(pglist,
					struct expose_pg_addrs, list);
				cur_vma = find_vma(taskmm,
					(unsigned long)epga->address);
				if (vma == cur_vma)
					return NULL;
			}
		}
	}

	return vma;
}

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
				unsigned long __user, address)
{
	/* Qiming Chen */
	struct mm_struct *mm;
	struct vm_area_struct *user_vma = NULL;
	struct vm_area_struct *curr_vma;
	struct expose_pg_addrs *pg_addrs;
	struct task_struct *task;
	int ret;
	
	/* self */
	if (pid == -1) {
		task = current;
		mm = current->mm;
	}
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
	user_vma = check_user_vma_is_valid(current->mm, address);
	if (!user_vma) {
		kfree(pg_addrs);
		up_read(&(mm->mmap_sem));
		return -EINVAL;
	}
	pg_addrs->address = (void*)address;

	/* add the new pg_addrs to the list */
	if (mm->pg_addrs)
		list_add(&(pg_addrs->list), &(mm->pg_addrs->list));
	else
		mm->pg_addrs = pg_addrs;

	/* get the list of VMAs */
	curr_vma = mm->mmap;

	/* go through the list of VMAs and copy the PTEs */
	do {
		ret = copy_ptes(mm, curr_vma, user_vma, (void*)address);
		if (ret < 0){
			/*
			if (mm->pg_addrs == pg_addrs)
				mm->pg_addrs == NULL;
			else
				list_remove(pg_addrs->list);
			kfree(pg_addrs);
			*/
			up_read(&(mm->mmap_sem));
			return ret;
		}
		curr_vma = curr_vma->vm_next;
	} while (curr_vma);

	/* unlock */
	up_read(&(mm->mmap_sem));

	return 0;
}
