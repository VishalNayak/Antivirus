#include <stdio.h>

int main(int argc, char* argv[], char* envp[]){
	FILE* f = fopen("sbu_ls", "r");
	if(!f){
		printf("Failed to open sbu_ls\n");
	}
	close(f);
	return 0;
}
