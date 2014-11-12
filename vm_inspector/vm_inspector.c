#include <stdio.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define PAGE_TABLE_SIZE (4*1024*1024) /* 4mb */

int main(int argc, char **argv)
{
	// int fd = open("/dev/zero", O_RDONLY);
	// unsigned int *addr = mmap(NULL, PAGE_TABLE_SIZE * 2, PROT_READ,
	// 			 MAP_SHARED, fd, 0);
	printf("shit%d \n", syscall(378, 0, 0, 0));
	return 0;
}
