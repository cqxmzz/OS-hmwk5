#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/syscalls.h>
#include <linux/init_task.h>

SYSCALL_DEFINE3(expose_page_table, pid_t, pid, unsigned long , fake_pgd,
    unsigned long, addr)
{
  return -5;
}
