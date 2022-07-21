#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>



int genNumber(int i)
{

	return i + 1337;
}

int main(void)
{

	srand(time(NULL)); // Initialization, should only be called once.

	// printf("%s\n", buffer);
	char* buffer = (char*)malloc(2048);
	strcpy(buffer, "nonfnoq'wdjmqnjfbalblabal\n");

	FILE *fptr;

	char *fname = (char *)malloc(256);
	char randpart[64];
	sprintf(randpart, "%d", rand());

	sprintf(fname, "out.%s.txt", randpart);
	fptr = fopen(fname, "w");

	if (fptr == NULL)
	{
		printf("Error!");
		exit(1);
	}

	fprintf(fptr, "%s", buffer);
	fclose(fptr);

	if(buffer[0] != 'n') {

		printf("target reached!\n");
	}


	for(;;) {

		int a = genNumber(rand());
		printf("Random number generated: %d\n", a);
		int i = 0;
		for(i= 0; i < 1000000;i++){}
	}

	return 0;
}
