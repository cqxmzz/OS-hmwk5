#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>

#define PAGE_TABLE_SIZE (4*1024*1024) /* 4mb */
#define PGD_SIZE (2048*4)

static int pgnum2index(int num)
{
	return (((num / 512 * 4096) / 4) + (num % 512));
}

#define young_bit(pte)  ((pte & (1<<1))  >> 1)
#define file_bit(pte)   ((pte & (1<<2))  >> 2)
#define dirty_bit(pte)  ((pte & (1<<6))  >> 6)
#define rdonly_bit(pte) ((pte & (1<<7))  >> 7)
/* citation
 http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0360f/BGEIHGIF.html
*/
#define xn_bit(pte)   ((pte & (1<<9))  >> 9)
#define phys(pte)   (pte >> 12)

static int expose(int pid, void *pgd_addr, void *addr)
{
	if (syscall(378, pid, (unsigned long)pgd_addr,
			(unsigned long)addr) < 0) {
		printf("Error: expose_page_table syscall\n");
		return -1;
	}
	if (pgd_addr == NULL)
		return -1;
	if (addr == NULL)
		return -1;
<<<<<<< HEAD
	/*
	 * printf("***********%p ", addr);
	 * int i = 0;
	 * for ( i = 0; i < PGD_SIZE * 2; i++) {
	 *	if (((unsigned long*)pgd_addr)[i] != 0)
	 *		printf("***********%d\n", i);
	 *}
	 */
=======

>>>>>>> 2016d2fcca1676f7f115df1f86315b0f83eb7f5f
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	unsigned long *page = NULL;
	/* unsigned long *pgd_i = NULL; */
	int pid;
	int verbose = 0;

	if(argc != 3 && argc != 2)
		return -1;

	if(argv[1][0] == '-' && argv[1][1] == 'v')
		verbose = 1;

	/* last argument is pid*/
	pid = atoi(argv[argc-1]);

	int fd = open("/dev/zero", O_RDONLY);
	unsigned long *pte_addr = mmap(NULL, PAGE_TABLE_SIZE * 2, PROT_READ,
				MAP_SHARED, fd, 0);
	unsigned long *pgd_addr = malloc(PGD_SIZE * 2 * sizeof(unsigned long));
	close(fd);

	if (pte_addr == MAP_FAILED) {
		printf("Error: mmap\n");
		return -1;
	}
	if (pgd_addr == MAP_FAILED) {
		printf("Error: mmap\n");
		return -1;
	}

	if(expose(pid, pgd_addr, pte_addr) < 0)
		return -1;

	/* iterate all entries of ptes */
	for (i = 0; i < PAGE_TABLE_SIZE / sizeof(int); i++) {
		page = &pte_addr[pgnum2index(i)];

		if (page == NULL)
			continue;
		if (*page == 0) {
			if (verbose)
				printf("0x400 0x10000000 0 0 0 0 0 0\n");
			continue;
		}
		printf("0x%x ", i/256);
		/* printf("%p", (void *)pgd_i[1]); */
		printf("0x%x ", i*4096);
		printf("%p ", (void *)phys(*page));
		printf("%lu ", young_bit(*page));
		printf("%lu ", file_bit(*page));
		printf("%lu ", dirty_bit(*page));
		printf("%lu ", rdonly_bit(*page));
		printf("%lu ", xn_bit(*page));
		printf("\n");
	}

	munmap(pte_addr, PAGE_TABLE_SIZE * 2);
	munmap(pgd_addr, PGD_SIZE * 2);

        pgd_addr = NULL;
	pte_addr = NULL;
        page = NULL;
        return 0;
}
