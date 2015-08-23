#include <stdio.h>

int main(int argc, char* argv[], char* envp[]){
	FILE* f = fopen("sbu_cp", "r");
	if(!f){
		printf("Failed to open sbu_cp\n");
	}
	close(f);
	return 0;
}
