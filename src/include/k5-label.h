#ifndef _KRB5_LABEL_H
#define _KRB5_LABEL_H

#ifdef THREEPARAMOPEN
#undef THREEPARAMOPEN
#endif
#ifdef WRITABLEFOPEN
#undef WRITABLEFOPEN
#endif

/* Wrapper functions which help us create files and directories with the right
 * context labels. */
#ifdef USE_SELINUX
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
FILE *krb5int_labeled_fopen(const char *path, const char *mode);
int krb5int_labeled_creat(const char *path, mode_t mode);
int krb5int_labeled_open(const char *path, int flags, ...);
int krb5int_labeled_mkdir(const char *path, mode_t mode);
int krb5int_labeled_mknod(const char *path, mode_t mode, dev_t device);
#define THREEPARAMOPEN(x,y,z) krb5int_labeled_open(x,y,z)
#define WRITABLEFOPEN(x,y) krb5int_labeled_fopen(x,y)
void *krb5int_push_fscreatecon_for(const char *pathname);
void krb5int_pop_fscreatecon(void *previous);
#else
#define WRITABLEFOPEN(x,y) fopen(x,y)
#define THREEPARAMOPEN(x,y,z) open(x,y,z)
#endif
#endif
