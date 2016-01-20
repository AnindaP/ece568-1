#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
foo ( char *arg )
{
	char	buf[256];
	int	i, len;

	len = strlen(arg);
	if (len > 272) len = 272;
    char str[] = "\x90\x0c\x01\x00\x00\xe0\xfd\x21\x20\00";
    int j = 0;
	for (i = 0; i <= len; i++) {
		//buf[i] = arg[i];
        if (i > 259) printf("len %d\ti %d\t\n", len, i);
        if (i >= 264) printf("buf %x\n", arg[i]);
        if(i >=267)
            buf[i] = str[j++];
        else buf[i] = arg[i];
        //else printf("\n");
    }
    printf("len %d\ti %d\n", len, i);


	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	int	t = 2;

	//printf ("Target2 running.\n");

    //printf("lb %x\n", argv[1][267]);

	if (argc != t)
	{
		//fprintf ( stderr, "target2: argc != 2\n" );
		exit ( EXIT_FAILURE );
	}

	foo ( argv[1] );

	return (0);
}
