#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>



int genNumber(int i)
{

	return i + 13637;
}


int genNumber1(int i)
{

	return i + 13337;
}

int genNumber2(int i)
{

	return i + 13137;
}

int genNumber3(int i)
{

	return i + 113337;
}

int genNumber4(int i)
{

	return i + 13337;
}

int genNumber5(int i)
{

	return i + 1338;
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
		a = genNumber1(rand());
		printf("Random number generated: %d\n", a);
		a = genNumber2(rand());
		printf("Random number generated: %d\n", a);
		
		a = genNumber3(rand());
		printf("Random number generated: %d\n", a);
		
		a = genNumber4(rand());
		printf("Random number generated: %d\n", a);
		a = genNumber5(rand());
		printf("Random number generated: %d\n", a);
		
		
		int i = 0;
		for(i= 0; i < 1000000;i++){}
	}

	return 0;
}
