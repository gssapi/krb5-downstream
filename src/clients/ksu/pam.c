/*
 * src/clients/ksu/pam.c
 *
 * Copyright 2007,2009,2010 Red Hat, Inc.
 *
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 *  Neither the name of Red Hat, Inc. nor the names of its contributors may be
 *  used to endorse or promote products derived from this software without
 *  specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Convenience wrappers for using PAM.
 */

#include "autoconf.h"
#ifdef USE_PAM
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "k5-int.h"
#include "pam.h"

#ifndef MAXPWSIZE
#define MAXPWSIZE 128
#endif

static int appl_pam_started;
static pid_t appl_pam_starter = -1;
static int appl_pam_session_opened;
static int appl_pam_creds_initialized;
static int appl_pam_pwchange_required;
static pam_handle_t *appl_pamh;
static struct pam_conv appl_pam_conv;
static char *appl_pam_user;
struct appl_pam_non_interactive_args {
	const char *user;
	const char *password;
};

int
appl_pam_enabled(krb5_context context, const char *section)
{
	int enabled = 1;
	if ((context != NULL) && (context->profile != NULL)) {
		if (profile_get_boolean(context->profile,
					section,
					USE_PAM_CONFIGURATION_KEYWORD,
					NULL,
					enabled, &enabled) != 0) {
			enabled = 1;
		}
	}
	return enabled;
}

void
appl_pam_cleanup(void)
{
	if (getpid() != appl_pam_starter) {
		return;
	}
#ifdef DEBUG
	printf("Called to clean up PAM.\n");
#endif
	if (appl_pam_creds_initialized) {
#ifdef DEBUG
		printf("Deleting PAM credentials.\n");
#endif
		pam_setcred(appl_pamh, PAM_DELETE_CRED);
		appl_pam_creds_initialized = 0;
	}
	if (appl_pam_session_opened) {
#ifdef DEBUG
		printf("Closing PAM session.\n");
#endif
		pam_close_session(appl_pamh, 0);
		appl_pam_session_opened = 0;
	}
	appl_pam_pwchange_required = 0;
	if (appl_pam_started) {
#ifdef DEBUG
		printf("Shutting down PAM.\n");
#endif
		pam_end(appl_pamh, 0);
		appl_pam_started = 0;
		appl_pam_starter = -1;
		free(appl_pam_user);
		appl_pam_user = NULL;
	}
}
static int
appl_pam_interactive_converse(int num_msg, const struct pam_message **msg,
			      struct pam_response **presp, void *appdata_ptr)
{
	const struct pam_message *message;
	struct pam_response *resp;
	int i, code;
	char *pwstring, pwbuf[MAXPWSIZE];
	unsigned int pwsize;
	resp = malloc(sizeof(struct pam_response) * num_msg);
	if (resp == NULL) {
		return PAM_BUF_ERR;
	}
	memset(resp, 0, sizeof(struct pam_response) * num_msg);
	code = PAM_SUCCESS;
	for (i = 0; i < num_msg; i++) {
		message = &(msg[0][i]); /* XXX */
		message = msg[i]; /* XXX */
		pwstring = NULL;
		switch (message->msg_style) {
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			printf("[%s]\n", message->msg ? message->msg : "");
			fflush(stdout);
			resp[i].resp = NULL;
			resp[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_PROMPT_ECHO_ON:
		case PAM_PROMPT_ECHO_OFF:
			if (message->msg_style == PAM_PROMPT_ECHO_ON) {
				if (fgets(pwbuf, sizeof(pwbuf),
					  stdin) != NULL) {
					pwbuf[strcspn(pwbuf, "\r\n")] = '\0';
					pwstring = pwbuf;
				}
			} else {
				pwstring = getpass(message->msg ?
						   message->msg :
						   "");
			}
			if ((pwstring != NULL) && (pwstring[0] != '\0')) {
				pwsize = strlen(pwstring);
				resp[i].resp = malloc(pwsize + 1);
				if (resp[i].resp == NULL) {
					resp[i].resp_retcode = PAM_BUF_ERR;
				} else {
					memcpy(resp[i].resp, pwstring, pwsize);
					resp[i].resp[pwsize] = '\0';
					resp[i].resp_retcode = PAM_SUCCESS;
				}
			} else {
				resp[i].resp_retcode = PAM_CONV_ERR;
				code = PAM_CONV_ERR;
			}
			break;
		default:
			break;
		}
	}
	*presp = resp;
	return code;
}
static int
appl_pam_non_interactive_converse(int num_msg,
				  const struct pam_message **msg,
				  struct pam_response **presp,
				  void *appdata_ptr)
{
	const struct pam_message *message;
	struct pam_response *resp;
	int i, code;
	unsigned int pwsize;
	struct appl_pam_non_interactive_args *args;
	const char *pwstring;
	resp = malloc(sizeof(struct pam_response) * num_msg);
	if (resp == NULL) {
		return PAM_BUF_ERR;
	}
	args = appdata_ptr;
	memset(resp, 0, sizeof(struct pam_response) * num_msg);
	code = PAM_SUCCESS;
	for (i = 0; i < num_msg; i++) {
		message = &((*msg)[i]);
		message = msg[i];
		pwstring = NULL;
		switch (message->msg_style) {
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			break;
		case PAM_PROMPT_ECHO_ON:
		case PAM_PROMPT_ECHO_OFF:
			if (message->msg_style == PAM_PROMPT_ECHO_ON) {
				/* assume "user" */
				pwstring = args->user;
			} else {
				/* assume "password" */
				pwstring = args->password;
			}
			if ((pwstring != NULL) && (pwstring[0] != '\0')) {
				pwsize = strlen(pwstring);
				resp[i].resp = malloc(pwsize + 1);
				if (resp[i].resp == NULL) {
					resp[i].resp_retcode = PAM_BUF_ERR;
				} else {
					memcpy(resp[i].resp, pwstring, pwsize);
					resp[i].resp[pwsize] = '\0';
					resp[i].resp_retcode = PAM_SUCCESS;
				}
			} else {
				resp[i].resp_retcode = PAM_CONV_ERR;
				code = PAM_CONV_ERR;
			}
			break;
		default:
			break;
		}
	}
	*presp = resp;
	return code;
}
static int
appl_pam_start(const char *service, int interactive,
	       const char *login_username,
	       const char *non_interactive_password,
	       const char *hostname,
	       const char *ruser,
	       const char *tty)
{
	static int exit_handler_registered;
	static struct appl_pam_non_interactive_args args;
	int ret = 0;
	if (appl_pam_started &&
	    (strcmp(login_username, appl_pam_user) != 0)) {
		appl_pam_cleanup();
		appl_pam_user = NULL;
	}
	if (!appl_pam_started) {
#ifdef DEBUG
		printf("Starting PAM up (service=\"%s\",user=\"%s\").\n",
		       service, login_username);
#endif
		memset(&appl_pam_conv, 0, sizeof(appl_pam_conv));
		appl_pam_conv.conv = interactive ?
				     &appl_pam_interactive_converse :
				     &appl_pam_non_interactive_converse;
		memset(&args, 0, sizeof(args));
		args.user = strdup(login_username);
		args.password = non_interactive_password ?
				strdup(non_interactive_password) :
				NULL;
		appl_pam_conv.appdata_ptr = &args;
		ret = pam_start(service, login_username,
				&appl_pam_conv, &appl_pamh);
		if (ret == 0) {
			if (hostname != NULL) {
#ifdef DEBUG
				printf("Setting PAM_RHOST to \"%s\".\n", hostname);
#endif
				pam_set_item(appl_pamh, PAM_RHOST, hostname);
			}
			if (ruser != NULL) {
#ifdef DEBUG
				printf("Setting PAM_RUSER to \"%s\".\n", ruser);
#endif
				pam_set_item(appl_pamh, PAM_RUSER, ruser);
			}
			if (tty != NULL) {
#ifdef DEBUG
				printf("Setting PAM_TTY to \"%s\".\n", tty);
#endif
				pam_set_item(appl_pamh, PAM_TTY, tty);
			}
			if (!exit_handler_registered &&
			    (atexit(appl_pam_cleanup) != 0)) {
				pam_end(appl_pamh, 0);
				appl_pamh = NULL;
				ret = -1;
			} else {
				appl_pam_started = 1;
				appl_pam_starter = getpid();
				appl_pam_user = strdup(login_username);
				exit_handler_registered = 1;
			}
		}
	}
	return ret;
}
int
appl_pam_acct_mgmt(const char *service, int interactive,
		   const char *login_username,
		   const char *non_interactive_password,
		   const char *hostname,
		   const char *ruser,
		   const char *tty)
{
	int ret;
	appl_pam_pwchange_required = 0;
	ret = appl_pam_start(service, interactive, login_username,
			     non_interactive_password, hostname, ruser, tty);
	if (ret == 0) {
#ifdef DEBUG
		printf("Calling pam_acct_mgmt().\n");
#endif
		ret = pam_acct_mgmt(appl_pamh, 0);
		switch (ret) {
		case PAM_IGNORE:
			ret = 0;
			break;
		case PAM_NEW_AUTHTOK_REQD:
			appl_pam_pwchange_required = 1;
			ret = 0;
			break;
		default:
			break;
		}
	}
	return ret;
}
int
appl_pam_requires_chauthtok(void)
{
	return appl_pam_pwchange_required;
}
int
appl_pam_session_open(void)
{
	int ret = 0;
	if (appl_pam_started) {
#ifdef DEBUG
		printf("Opening PAM session.\n");
#endif
		ret = pam_open_session(appl_pamh, 0);
		if (ret == 0) {
			appl_pam_session_opened = 1;
		}
	}
	return ret;
}
int
appl_pam_setenv(void)
{
	int ret = 0;
#ifdef HAVE_PAM_GETENVLIST
#ifdef HAVE_PUTENV
	int i;
	char **list;
	if (appl_pam_started) {
		list = pam_getenvlist(appl_pamh);
		for (i = 0; ((list != NULL) && (list[i] != NULL)); i++) {
#ifdef DEBUG
			printf("Setting \"%s\" in environment.\n", list[i]);
#endif
			putenv(list[i]);
		}
	}
#endif
#endif
	return ret;
}
int
appl_pam_cred_init(void)
{
	int ret = 0;
	if (appl_pam_started) {
#ifdef DEBUG
		printf("Initializing PAM credentials.\n");
#endif
		ret = pam_setcred(appl_pamh, PAM_ESTABLISH_CRED);
		if (ret == 0) {
			appl_pam_creds_initialized = 1;
		}
	}
	return ret;
}
#endif
