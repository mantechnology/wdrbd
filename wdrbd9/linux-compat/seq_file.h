#ifndef __SEQ_FILE_H__
#define __SEQ_FILE_H__
#include "drbd_windrv.h"

int seq_putc(struct seq_file *m, char c);
int seq_puts(struct seq_file *m, const char *s);

#endif