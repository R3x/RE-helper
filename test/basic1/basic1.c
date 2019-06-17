#include <stdio.h>

int main() {
	char inp[30];
	printf("Hello \n");
	fgets(inp, 30, stdin);
	printf("%s", inp);
	return 0;
}
