/*  */

/*
 * Blame: Roland Dowdeswell <elric@imrryr.org>
 *
 * This is a small wrapper script that calls krb5_keytabc.  The latter
 * program must run as root in order to access /etc/krb5.keytab.  In the
 * wrapper, we eliminate and sanitise the environment and add an argument
 * specifying what Production ID we are operating as so that krb5_keytabc
 * can apply the appropriate ACLs.  We also parse and regenerate the command
 * line arguments---just in case...
 */

#include <sys/types.h>

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef KRB5_KEYTABC_PATH
#error KRB5_KEYTABC_PATH must be defined during compiler invocation
#endif

#define MAXVEES	9

void
usage(void)
{
	const char	*new_argv[] = { KRB5_KEYTABC_PATH, "-?", NULL };
	uid_t		 uid;
	uid_t		 uid2;

	uid = getuid();
	if (setuid(uid) == -1) {
		perror("setuid");
		exit(EXIT_FAILURE);
	}

	uid2 = getuid();
	if (uid != uid2) {
		fprintf(stderr, "Inexplicable failure: you must be using "
		    "linux...\n");
		exit(EXIT_FAILURE);
	}

	execve(KRB5_KEYTABC_PATH, (char **)new_argv, NULL);
	fprintf(stderr, "Can't execute %s: %s\n", KRB5_KEYTABC_PATH,
	    strerror(errno));
	exit(1);
}

char *
get_user(void)
{
	struct passwd	*pwd;
	uid_t		 uid;

	uid = getuid();
	pwd = getpwuid(uid);
	if (pwd == NULL) {
		fprintf(stderr, "Can not determine proid name for uid=%d\n",
		    (int)uid);
		usage();
	}
	return strdup(pwd->pw_name);
}

int
main(int argc, char **argv)
{
	extern int	  optind;
	int		  c;
	int		  i;
	int		  new_argc;
	int		  Aflag = 0;
	int		  Fflag = 0;
	int		  Zflag = 0;
	int		  cflag = 0;
	int		  fflag = 0;
	int		  gflag = 0;
	int		  lflag = 0;
	int		  qflag = 0;
	int		  tflag = 0;
	int		  vflag = 0;
	char		 *libs = NULL;
	char		 *proid = NULL;
	char		**new_argv;
	char		 *user;
	char		 *xrealm = NULL;

	while ((c = getopt(argc, argv, "AFL:RX:Zcfglqp:rtv?")) != -1)
		switch (c) {
		case 'A':
			Aflag = 1;
			break;
		case 'F':
			Fflag = 1;
			break;
		case 'L':
			if (libs) {
				fprintf(stderr, "can't specify more than one "
				    "supported Kerberos library version.\n");
				usage();
			}
			libs = strdup(optarg);
			break;
		case 'X':
			if (xrealm) {
				fprintf(stderr, "can't specify more than one "
				    "realm from which to xrealm bootstrap.\n");
				usage();
			}
			xrealm = strdup(optarg);
			break;
		case 'Z':
			Zflag = 1;
			break;
		case 'c':
			cflag = 1;
			break;
		case 'f':
			fflag = 1;
			break;
		case 'g':
			gflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
		case 'q':
			qflag = 1;
			break;
		case 'p':
			if (proid) {
				fprintf(stderr, "can't specify more than "
				    "one proid.\n");
				usage();
			}
			proid = strdup(optarg);
			break;
		case 't':
			tflag = 1;
			break;
		case 'v':
			if (vflag < MAXVEES)
				vflag++;
			break;
		/* R and r are deprecated, but simply do nothing... */
		case 'R':
		case 'r':
			break;
		case '?':
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (cflag + gflag + lflag + qflag + tflag > 1) {
		fprintf(stderr, "Only one of -c, -g, -l, -q or -t may be "
		    "specified.\n\n");
		usage();
	}

	user = get_user();

	new_argc = argc + 3;
	if (proid)
		new_argc += 2;
	if (libs)
		new_argc += 2;

	new_argc += Aflag + cflag + fflag + gflag;
	new_argc += lflag + qflag + tflag + vflag;
	new_argc += 10; /*XXXrcd: safety*/

	i = 0;
	new_argv = (char **)malloc((new_argc+1) * sizeof(*new_argv));
	new_argv[i++] = strdup(KRB5_KEYTABC_PATH);
	new_argv[i++] = strdup("-u");
	new_argv[i++] = get_user();

	if (libs) {
		new_argv[i++] = strdup("-L");
		new_argv[i++] = libs;
	}

	if (xrealm) {
		new_argv[i++] = strdup("-X");
		new_argv[i++] = xrealm;
	}

	if (proid) {
		new_argv[i++] = strdup("-p");
		new_argv[i++] = proid;
	}

	if (Aflag)
		new_argv[i++] = strdup("-A");
	if (Fflag)
		new_argv[i++] = strdup("-F");
	if (Zflag)
		new_argv[i++] = strdup("-Z");
	if (cflag)
		new_argv[i++] = strdup("-c");
	if (fflag)
		new_argv[i++] = strdup("-f");
	if (gflag)
		new_argv[i++] = strdup("-g");
	if (lflag)
		new_argv[i++] = strdup("-l");
	if (qflag)
		new_argv[i++] = strdup("-q");
	if (tflag)
		new_argv[i++] = strdup("-t");
	if (vflag) {
		char	*vees;

		if (vflag > MAXVEES)
			vflag = MAXVEES;
		vees = strdup("-vvvvvvvvv");
		vees[vflag + 1] = '\0';
		new_argv[i++] = vees;
	}

	while (argc--)
		new_argv[i++] = *argv++;

	new_argv[i++] = NULL;

	if (vflag > 2) {
		fprintf(stderr, "Building argument list to call "
		    "krb5_keytabc:\n");

		for (i=0; new_argv[i]; i++)
			fprintf(stderr, "arg %d: %s\n", i, new_argv[i]);
	}

	if (setuid(0) == -1) {
		fprintf(stderr, "can't set real user ID to root\n");
		exit(1);
	}

	/* XXXrcd: check this out a tad... */
	execve(KRB5_KEYTABC_PATH, new_argv, NULL);

	fprintf(stderr, "failed to exec %s, %s.\n", KRB5_KEYTABC_PATH,
	    strerror(errno));
	exit(1);
}
