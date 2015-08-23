#include <stdio.h>

int main(int argc, char* argv[], char* envp[]){
	FILE* f = fopen("sbu_grep", "r");
	if(!f){
		printf("Failed to open sbu_grep\n");
	}
	close(f);
	return 0;
}
