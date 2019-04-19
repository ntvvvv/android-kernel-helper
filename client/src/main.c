#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <fcntl.h>


#define REDFINGER_DEV "redfinger"
#define CMD_BASE 0xC0000000
#define REDF_SET_UID  (CMD_BASE + 1)

int get_uid_by_pkg(char* pkg) {
    FILE* fp = fopen("/data/system/packages.list", "r");
    
    if (fp == NULL) {
        printf("permission error\n");
        return 0;
    }
    char linestr[1024] = { 0 };
    char pkgname[256] = { 0 };
    int found_uid = 0;
    int uid = 0;
    while (!feof(fp)) {
        fgets(linestr, sizeof(linestr), fp);
        memset(pkgname, 0, sizeof(pkgname));
        uid = 0;
        int count = sscanf(linestr, "%s %d", pkgname, &uid);
        if (count == 2) {
            if (!strcmp(pkg, pkgname)) {
                found_uid = uid;
                break;
            }
        }
    }
    return found_uid;
}

int main(int argc, char const *argv[]){
    if (argc < 2) {
        printf("rfc <pkg>\n");
        return -1;
    }
    int uid = get_uid_by_pkg(argv[1]);
    if (uid == 0) {
        printf("didn't found uid for pkg[%s]\n", argv[1]);
        return -1;
    }
    printf("get uid[%d] by pkg[%s]\n", uid, argv[1]);
    int fd = open("/dev/"REDFINGER_DEV, O_RDWR);
	if(fd == -1){
		printf("open error, check USER!\n");
		return -1;
	}
    printf("open dev ret %d\n", fd);
	ioctl(fd, REDF_SET_UID, uid);
	close(fd);

    return 0;
}