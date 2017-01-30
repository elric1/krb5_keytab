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

#include <err.h>
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

#define OPT_WITHOUTARG(x) do {						\
		if (x ## flag ) {					\
			new_argv[i++] = strdup("-" #x);			\
		}							\
		if (i >= new_argc) {					\
			fprintf(stderr, "Memory allocation error.\n");	\
			exit(1);					\
		}							\
	} while (0)

#define OPT_WITHARG(x, var)	do {					\
		if (var) {						\
			new_argv[i++] = strdup("-" #x);			\
			new_argv[i++] = var;				\
		}							\
		if (i >= new_argc) {					\
			fprintf(stderr, "Memory allocation error.\n");	\
			exit(1);					\
		}							\
	} while (0)

static void
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

static char *
get_user(void)
{
	struct passwd	*pwd;
	uid_t		 uid;

	uid = getuid();
	pwd = getpwuid(uid);
	if (pwd == NULL) {
		fprintf(stderr, "Can not determine user name for uid=%d\n",
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
	int		  ret;
	int		  new_argc;
	int		  Aflag = 0;
	int		  Fflag = 0;
	int		  Uflag = 0;
	int		  Zflag = 0;
	int		  cflag = 0;
	int		  fflag = 0;
	int		  gflag = 0;
	int		  lflag = 0;
	int		  qflag = 0;
	int		  tflag = 0;
	int		  vflag = 0;
	int		  wflag = 0;
	char		 *ktroot = NULL;
	char		 *libs = NULL;
	char		**new_argv;
	char		 *user = NULL;
	char		 *winxrealm = NULL;
	char		 *xrealm = NULL;

	while ((c = getopt(argc, argv, "AFL:R:UW:X:Zcfglqp:tvw?")) != -1)
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
		case 'R':
			if (getuid() != 0) {
				fprintf(stderr, "The '-R' option is restricted "
				    "to the superuser.\n");
				usage();
			}
			if (ktroot) {
				fprintf(stderr, "can't specify -R multiple "
				    "times.\n");
				usage();
			}
			ktroot = strdup(optarg);
			break;
		case 'U':
			Uflag = 1;
			break;
		case 'W':
			if (winxrealm) {
				fprintf(stderr, "can't specify more than one "
				    "windows principal from which to xrealm "
				    "bootstrap.\n");
				usage();
			}
			xrealm = strdup(optarg);
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
			if (user) {
				fprintf(stderr, "can't specify more than "
				    "one user.\n");
				usage();
			}
			user = strdup(optarg);
			break;
		case 't':
			tflag = 1;
			break;
		case 'v':
			if (vflag < MAXVEES)
				vflag++;
			break;
		case 'w':
			wflag = 1;
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

	/*
	 * We overestimate the size of new_argc to be safe, to ensure
	 * that programming errors will not result in a buffer overflow.
	 * The size is: the original argument size + 3 + all of the options
	 * that we add.  And then we add ten just in case.
	 */

	new_argc = argc + 3;
	new_argc += Aflag + Fflag + Uflag + Zflag + cflag + fflag;
	new_argc += gflag + lflag + qflag + tflag + vflag + wflag;
	new_argc += (ktroot?2:0) + (libs?2:0) + (winxrealm?2:0);
	new_argc += (xrealm?2:0) + (user?2:0);
	new_argc += 10;

	i = 0;
	new_argv = (char **)malloc((new_argc+1) * sizeof(*new_argv));
	new_argv[i++] = strdup(KRB5_KEYTABC_PATH);
	new_argv[i++] = strdup("-u");
	new_argv[i++] = get_user();

	OPT_WITHARG(R, ktroot);
	OPT_WITHARG(L, libs);
	OPT_WITHARG(W, winxrealm);
	OPT_WITHARG(X, xrealm);
	OPT_WITHARG(p, user);

	OPT_WITHOUTARG(A);
	OPT_WITHOUTARG(F);
	OPT_WITHOUTARG(U);
	OPT_WITHOUTARG(Z);
	OPT_WITHOUTARG(c);
	OPT_WITHOUTARG(f);
	OPT_WITHOUTARG(g);
	OPT_WITHOUTARG(l);
	OPT_WITHOUTARG(q);
	OPT_WITHOUTARG(t);
	OPT_WITHOUTARG(w);

	if (vflag) {
		char	*vees;

		if (vflag > MAXVEES)
			vflag = MAXVEES;
		vees = strdup("-vvvvvvvvv");
		vees[vflag + 1] = '\0';
		new_argv[i++] = vees;
		if (i >= new_argc) {
			fprintf(stderr, "Memory allocation error.\n");
			exit(1);
		}
	}

	while (argc--) {
		new_argv[i++] = *argv++;
		if (i >= new_argc) {
			fprintf(stderr, "Memory allocation error.\n");
			exit(1);
		}
	}

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

	/* We ignore the return because it's not essential */
	ret = chdir("/");
	if (ret == -1)
		warn("Could not chdir(\"/\")");

	/* XXXrcd: check this out a tad... */
	execve(KRB5_KEYTABC_PATH, new_argv, NULL);

	fprintf(stderr, "failed to exec %s, %s.\n", KRB5_KEYTABC_PATH,
	    strerror(errno));
	exit(1);
}
