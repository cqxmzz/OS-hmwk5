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
// #define pg_num_to_idx(num) (((num / 512 * 4096) / 4) + (num % 512))

static int pgnum2index(int num)
{
	return (((num / 512 * 4096) / 4) + (num % 512));
}
#define young_bit     (1 << 1)
#define file_bit      (1 << 2)
#define dirty_bit     (1 << 6)
#define rdonly_bit    (1 << 7)
#define user_bit      (1 << 8)

#define get_young_bit(pte)  ((pte & young_bit)  >> 1)
#define get_file_bit(pte)   ((pte & file_bit)   >> 2)
#define get_dirty_bit(pte)  ((pte & dirty_bit)  >> 6)
#define get_rdonly_bit(pte) ((pte & rdonly_bit) >> 7)
#define get_user_bit(pte)   ((pte & user_bit)   >> 8)
#define get_phys(pte)   (pte >> 12)

static void * expose(int pid)
{
	/* int i;
	int fault; */
	int fd = open("/dev/zero", O_RDONLY);
	void *addr = mmap(NULL, PAGE_TABLE_SIZE * 2, PROT_READ,
				 MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		printf("Error: mmap");
		return NULL;
	}
	/* Fault now to avoid handling in kernel */
	/* for (i = 0; i < (PAGE_TABLE_SIZE * 2) / 4; ++i)
		fault = addr[i]; */
	if (syscall(378, pid, 0, (unsigned long)addr) < 0) {
		printf("Error: expose_page_table syscall");
		return NULL;
	}
	return addr;
}

int main(int argc, char **argv)
{
	int i;
	void *page_table = NULL, *page = NULL;
	int pid;
	bool verbose = false;

	if(argc != 2)
		return -1

	if(argv[0][0] == '-' && argv[0][1] == 'v')
		verbose = true;

	/* second argument is pid*/
	pid = atoi(argv[1]);

	page_table = expose(pid);

	if (page_table == NULL) {
		if (verbose) {
			printf("0x400 0x10000000 0 0 0 0 0 0\n");
			return 0;
		}
		return -1;
	}

	for (i = 0; i < PAGE_TABLE_SIZE / sizeof(int); i++) {
		page = &page_table[pgnum2index(i)];

		if (page == NULL)
			continue;
		if (*page == 0)
			continue;
		printf("%d ", i);
		printf("%p ", page);
		printf("%p ", (void *)phys(*page));
		printf("%d ", young_bit(*page));
		printf("%d ", file_bit(*page));
		printf("%d ", dirty_bit(*page));
		printf("%d ", rdonly_bit(*page));
		printf("%d ", user_bit(*page));
		printf("\n");
	}
	
	free(page_table);
	free(page);
	page_table = NULL;
	page = NULL;
	return 0;
}
