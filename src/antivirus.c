#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <binary.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int is_path_a_folder(char *path);
int folder_scan(char *path);
void binary_scan(char* binary);
int check_in_blacklist(char* binary, char** details);
int check_in_whitelist(unsigned char* sha1);
int compare_hashes(unsigned char* sha1, char* line);
int search_virus_sig_in_binary(char* black_entry, char* binary);
void log_to_file(char*msg);

char msg[200];

void log_to_file(char*msg){
	char fpath[100];
	sprintf(fpath,"/tmp/antivirus.log");
	umask(1);
	int fd = open(fpath, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd < 0) {
		printf("Failed to open %s\n", fpath);
	}
	write(fd, msg, strlen(msg));
	close(fd);
}

int is_path_a_folder(char *path)
{
	struct stat stbuf;
	if(stat(path,&stbuf ) == -1 )
	{
		printf("Unable to stat file: %s\n", path) ;
		return -1;
	}
	if ((stbuf.st_mode & 0xf000) == 0x4000)
		return 1;
	else
		return 0;

	return -1;
}

int search_virus_sig_in_binary(char* black_entry, char* binary){
	char b_entry[256];
	strcpy(b_entry, black_entry);
	char* sign = strchr(b_entry, ',')+1;
	char* entry = strtok(sign," ");
	char* virus_entries[20];int i = 0;
	int ret_val = -1;
	while(entry){
		virus_entries[i++] = entry;
		entry = strtok(NULL," ");
	}

	char *bin_arr = NULL;
	unsigned int bin_sz = 0;

	int ret = read_binary(binary, &bin_arr, &bin_sz);
	if (ret < 0)
		return ret;

	unsigned int j = 0;
	int match = 0;
	int a = 0;
	for(j=0;j<bin_sz;j++){
		match = 1;
		for(i=0;i<20;i++){
			a = (int)strtol(virus_entries[i], NULL, 16);
			if((bin_arr[j+i] & 0xff) != a){
				match = 0;
				break;
			}
		}
		if(match){
			ret_val = 0;
#if 0
			printf("Virus signature at an offset of %d bytes in the binary!\n", j);
#endif
			break;
		}
	}
	return ret_val;
}

int check_in_blacklist(char* binary, char** details){
	char line[256];

	char fpath[100];
	sprintf(fpath, "/etc/netcop/blacklist");
	FILE* f_blacklist = fopen(fpath, "r");
	if (!f_blacklist) {
		printf("unable to open blacklist file\n");
		return -1;
	}
	int ret_val = 1;

	while(!feof(f_blacklist)){
		if(fgets(line, 256, f_blacklist)){
			if(!search_virus_sig_in_binary(line, binary)){
				*details = (char*) malloc(strlen(line)*sizeof(char));
				strcpy(*details, line);
				ret_val = 0;
				break;
			}
		}
	}

	return ret_val;
}

int compare_hashes(unsigned char* sha1, char* line){
	char str[2];
	int a = 0;
	int ret_val = 0;
	int i = 0;
	int j;
	for(i=0,j=0;i<20 && j<40;i++,j+=2){
		str[0] = line[j];
		str[1] = line[j+1];
		a = (int)strtol(str, NULL, 16);
		if(sha1[i] != a){
			ret_val = -1;
		}
	}
	return ret_val;
}

int check_in_whitelist(unsigned char* sha1){
	char line[256];
	char fpath[100];
	sprintf(fpath,"/etc/netcop/whitelist");
	FILE* f_whitelist = fopen(fpath, "r");
	if (!f_whitelist) {
		printf("unable to open whitelist file\n");
		return -1;
	} 
	int ret_val = 1;
	while(!feof(f_whitelist)){
		if(fgets(line, 256, f_whitelist)){
			if(!compare_hashes(sha1, line)){
				ret_val = 0;
				break;
			}
		}
	}
	log_to_file(msg);
	return ret_val;
}
int folder_scan(char *path)
{
	struct dirent *dp;
	DIR *dfd;

	if((dfd = opendir(path)) == NULL)
	{
		printf("Can't open %s\n", path);
		return -1;
	}

	char filename_qfd[100] ;
	while ((dp = readdir(dfd)) != NULL)
	{
		struct stat stbuf ;
		sprintf(filename_qfd, "%s/%s",path,dp->d_name) ;
		if(stat(filename_qfd,&stbuf ) == -1 )
		{
			printf("Unable to stat file: %s\n",filename_qfd) ;
			continue ;
		}
		if((stbuf.st_mode & 0xf000) == 0x4000)
		{
			continue;
		}
		else
		{
			binary_scan(filename_qfd);
			printf("\n");
		}
	}
	return 0;
}

void binary_scan(char* binary){

	printf("Scanning %s ...\n", binary);

	char *bin_arr = NULL;
	unsigned int bin_sz = 0;

	int ret = read_binary(binary, &bin_arr, &bin_sz);
	if (ret < 0)
		return;

	//Printing Signature of binary. Random 20 bytes inside binary.
#if 0
	int i;
	for(i=bin_sz-20;i<bin_sz-0;i++){
		printf("%02x ", bin_arr[i]&0xff);
	}
	printf("\n");
	printf("Size of %s: %d bytes.\n", binary, bin_sz);
#endif

	unsigned char sha1[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, bin_arr, bin_sz);
	SHA1_Final(sha1, &ctx);
#if 0
	printf("SHA1 of %s: ", binary);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
		printf("%02x", sha1[i]);
	}
	printf("\n");
#endif
	char* details;
	ret = check_in_whitelist(sha1);
	if (ret < 0) {
		printf("Failed to check whitelist\n");
		sprintf(msg,"[%s] failed to check whitelist\n",binary);
		log_to_file(msg);
	} else if (ret == 0) {
		printf("Present in Whitelist. Binary is safe to execute.\n");
		sprintf(msg,"[%s]Present in Whitelist. Binary is safe to execute.\n",binary);
		log_to_file(msg);
		return;
	}
	ret = check_in_blacklist(binary, &details);
	if (ret < 0) {
		printf("Failed to check blacklist. Antivirus check failed.\n");
		sprintf(msg,"[%s] failed to check blacklist. Antivirus check failed\n",binary);
		log_to_file(msg);
		return;
	} else if (ret == 0) {
		printf("Virus Found! Details:%s", details);
		/* DO NOT CHANGE BELOW LINE WITHOUT WRITTEN PERMISSION*/
		sprintf(msg,"[%s]Virus Found! Details:%s\n",binary, details);
		log_to_file(msg);
		return;
	} 

	printf("File didn't match with any of virus database. Not likely a virus.\n");
	printf(msg,"[%s] File didn't match with any of virus database. Not likely a virus.\n",binary);
	log_to_file(msg);
}


int main(int argc, char *argv[], char* envp[])
{
	char cwd[100];
	int ret;

	if (argc < 2 || argc > 3) {
		printf
			("Usage: antivirus <-options> <folder_name/binary_name>\nOptions:\n\t-scan: Scanning the binary for virus\n\t-update: Updating the virus database\n");
		return 0;
	}

	getcwd(cwd,100);
	//To print in STDOUT when running on-demand as a user process
#if 0
	printf("pwd=%s argc=%d ", cwd, argc);

	int i;
	for (i = 0; i < argc; i++) {
		printf("argv[%d]=%s ", i, argv[i]);
	}
	printf("\n");
#endif

	if (!strcmp(argv[1], "-scan")) {
		if (argc != 3) {
			printf("Usage: antivirus <-options> <binary_name>\nOptions:\n\t-scan: Scanning the binary for virus\n\t-update: Updating the virus database\n");
			return 0;
		}
		int is_folder = is_path_a_folder(argv[2]);
		if (!is_folder) {
			binary_scan(argv[2]);
		} else if (is_folder == 1) {
			folder_scan(argv[2]);
		} else {
			printf("File/Folder not found\n");
		}

	} else if (!strcmp(argv[1], "-update")) {
		ret = update_antivirus();
		if (ret < 0) {
			printf("Antivirus update failed\n");
		} else if (ret == 0) {
			printf("Antivirus files whitelist, blacklist updated successfully\n");
		}
	} else {
		printf
			("Usage: antivirus <-options> <binary_name>\nOptions:\n\t-scan: Scanning the binary for virus\n\t-update: Updating the virus database\n");
	}
	return 0;
}
