#include <stdio.h>

int main(int argc, char* argv[], char* envp[]){
	FILE* f = fopen("sbu_rm", "r");
	if(!f){
		printf("Failed to open sbu_rm\n");
	}
	close(f);
	return 0;
}
