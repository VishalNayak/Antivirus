#include <stdio.h>

int main(int argc, char* argv[], char* envp[]){
	FILE* f = fopen("sbu_ps", "r");
	if(!f){
		printf("Failed to open sbu_ps\n");
	}
	close(f);
	return 0;
}
