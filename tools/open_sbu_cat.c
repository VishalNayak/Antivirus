#include <stdio.h>

int main(int argc, char* argv[], char* envp[]){
	FILE* f = fopen("sbu_cat", "r");
	if(!f){
		printf("Failed to open sbu_cat\n");
	}
	close(f);
	return 0;
}
