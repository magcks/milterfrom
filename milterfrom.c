/* 
 * Milterfrom
 * 
 * Copyright (c) 2017, Max von Buelow
 * All rights reserved.
 * Contact: https://maxvonbuelow.de
 * 
 * This file is part of the MilterFrom project.
 * https://github.com/magcks/milterfrom
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "libmilter/mfapi.h"
#include "libmilter/mfdef.h"

struct mlfiPriv {
	int is_auth;
	char *env_from;
	int env_from_len;
	int reject;
};

#define MLFIPRIV ((struct mlfiPriv*)smfi_getpriv(ctx))

static unsigned long mta_caps = 0;

// Function to extract addresses from the header/envelope fields.  If the field
// contains a < with a subsequent >, the inner part is used. If not, the whole
// header field is used. This allows matching "Max Mustermann
// <max.mustermann@example.invalid>" matching.
const char *parse_address(const char *address, size_t *len)
{
	size_t inlen = strlen(address);
	size_t pos_open = -1, pos_close = -1;
	size_t i;
	for (i = 0; i < inlen; ++i) {
		if (address[i] == '<') pos_open = i;
		else if (address[i] == '>') pos_close = i;
	}

	if (pos_open != -1 && pos_close != -1 && pos_open < pos_close) {
		*len = pos_close - pos_open - 1;
		return address + pos_open + 1;
	} else {
		*len = inlen;
		return address;
	}
}

void mlfi_cleanup(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;

	if (priv == NULL) return;

	free(priv->env_from);
	free(priv);
	smfi_setpriv(ctx, NULL);
}

sfsistat mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	struct mlfiPriv *priv;
	char *fromcp = NULL;

	// Allocate some private memory.
	priv = calloc(1, sizeof(*priv));
	if (priv == NULL) {
		goto fail;
	}

	// Parse envelope from.
	size_t len = 0;
	const char *from = parse_address(*envfrom, &len);
	if (len == 0) {
		/* The strndup call below with a length of 0 will allocate a string of size
		 * 0 so avoid that entirely and fail. */
		goto fail;
	}
	fromcp = strndup(from, len);
	if (fromcp == NULL) {
		goto fail;
	}

	// Set private values.
	priv->is_auth = smfi_getsymval(ctx, "{auth_type}") ? 1 : 0;
	priv->env_from = fromcp;
	priv->env_from_len = len;
	priv->reject = 0;

	smfi_setpriv(ctx, priv);

	return SMFIS_CONTINUE;
fail:
	free(fromcp);
	return SMFIS_TEMPFAIL;
}

sfsistat mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct mlfiPriv *priv = MLFIPRIV;

	// Perform checks if the sender is authenticated and the message is not rejected yet (the mail may contain multiple from tags, all have to match!).
	if (priv->is_auth && !priv->reject) {
		if (strcasecmp(headerf, "from") == 0) {
			size_t len = 0;
			const char *from = parse_address(headerv, &len);

			// Check whether header from matches envelope from and reject if not.
			if (len != priv->env_from_len || strncasecmp(from, priv->env_from, len) != 0) priv->reject = 1;
		}
	}

	return ((mta_caps & SMFIP_NR_HDR) != 0) ? SMFIS_NOREPLY : SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX *ctx)
{
	struct mlfiPriv *priv = MLFIPRIV;
	if (priv->reject) {
		smfi_setreply(ctx, "550", "5.7.1", "Rejected due to unmatching envelope and header sender.");
		mlfi_cleanup(ctx);
		return SMFIS_REJECT;
	}
	mlfi_cleanup(ctx);
	return SMFIS_CONTINUE;
}


sfsistat mlfi_abort(SMFICTX *ctx)
{
	mlfi_cleanup(ctx);
	return SMFIS_CONTINUE;
}

sfsistat mlfi_negotiate(SMFICTX *ctx, unsigned long f0, unsigned long f1, unsigned long f2, unsigned long f3, unsigned long *pf0, unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
	*pf0 = 0;
	/* milter protocol steps: all but connect, HELO, RCPT */
	*pf1 = SMFIP_NOCONNECT | SMFIP_NOHELO | SMFIP_NORCPT;
	mta_caps = f1;
	if ((mta_caps & SMFIP_NR_HDR) != 0) *pf1 |= SMFIP_NR_HDR;
	*pf2 = 0;
	*pf3 = 0;
	return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
{
	"Header from check", /* filter name */
	SMFI_VERSION,        /* version code -- do not change */
	0,                   /* flags */
	NULL,                /* connection info filter */
	NULL,                /* SMTP HELO command filter */
	mlfi_envfrom,        /* envelope sender filter */
	NULL,                /* envelope recipient filter */
	mlfi_header,         /* header filter */
	NULL,                /* end of header */
	NULL,                /* body block filter */
	mlfi_eom,            /* end of message */
	mlfi_abort,          /* message aborted */
	NULL,                /* connection cleanup */
	NULL,                /* unknown/unimplemented SMTP commands */
	NULL,                /* DATA command filter */
	mlfi_negotiate       /* option negotiation at connection startup */
};

uid_t get_uid(const char *name)
{
    struct passwd *pwd = getpwnam(name);
    return pwd == NULL ? -1 : pwd->pw_uid;
}
gid_t get_gid(const char *name)
{
    struct group *grp = getgrnam(name);
    return grp == NULL ? -1 : grp->gr_gid;
}

int main(int argc, char **argv)
{
	int c, daemonize = 0;
	uid_t uid = -1; gid_t gid = -1;
	mode_t um = -1;
	char *pidfilename = NULL, *sockname = NULL;
	FILE *pidfile = NULL;

	while ((c = getopt(argc, argv, "ds:p:u:g:m:")) != -1) {
		switch (c) {
		case 's':
			sockname = strdup(optarg);
			break;
		case 'p':
			pidfilename = strdup(optarg);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'u':
			uid = get_uid(optarg);
			break;
		case 'g':
			gid = get_gid(optarg);
			break;
		case 'm':
			um = strtol(optarg, 0, 8);
			break;
		}
	}

	if (!sockname) {
		fprintf(stderr, "%s: Missing required -s argument\n", argv[0]);
		exit(EX_USAGE);
	}

	if (pidfilename) {
		unlink(pidfilename);
		pidfile = fopen(pidfilename, "w");
		if (!pidfile)
		{
			fprintf(stderr, "Could not open pidfile: %s\n", strerror(errno));
			exit(1);
		}
		free(pidfilename);
	}

	if (um != (mode_t)-1) umask(um);
	if (gid != (gid_t)-1) setgid(gid);
	if (uid != (uid_t)-1) setuid(uid);

	if (daemonize) {
		if (daemon(0, 0) == -1) {
			fprintf(stderr, "daemon() failed: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (pidfile) {
		fprintf(pidfile, "%ld\n", (long)getpid());
		fclose(pidfile);
	}

	struct stat junk;
	if (stat(sockname, &junk) == 0) unlink(sockname);
	smfi_setconn(sockname);
	free(sockname);

	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	}
	return smfi_main();
}
