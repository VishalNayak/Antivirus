#include <stdio.h>
#include <stdlib.h>
#include <binary.h>

int read_binary(char* path, char** p_bin, unsigned int* size){
    FILE* f = fopen(path, "rb");
    if (!f) {
	printf("Fopen failed\n");
	return -1;
    }
	
    int n = 0;
    char ch;
    while(!feof(f)){
        n += fread(&ch, 1, 1, f);
    }
    fclose(f);

    char* binary = (char*) malloc(n);

    f = fopen(path,"rb");
    int i=0;
    while(!feof(f)){
        fread(&ch, 1, 1, f);
        binary[i++] = ch;
    }
//    fclose(f);

    *p_bin = binary;
    *size = n;
    return 0;
}
