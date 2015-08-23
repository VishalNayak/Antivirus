#include <stdio.h>
#include <stdlib.h>
#include <binary.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <unistd.h>

size_t temp_fwrite(void *buff,size_t size,size_t n,void *s);
int av_update(char *whichlist);

struct FtpFile 
{
	const char *filename;
	FILE *stream;
};
//char top[200];

int update_antivirus()
{
	int ret;
	ret = setuid(0);
	if (ret < 0) {
		printf("Permission denied. Try running as sudo\n");
		return ret;
	}
	ret = av_update("whitelist");
	if (ret < 0) {
		printf("failed to update whitelist\n");
		return ret;
	}
	ret = av_update("blacklist");
	if (ret < 0) {
		printf("failed to update blacklist\n");
		return ret;
	}
	return 0;
}

int av_update(char *whichlist)
{
	char fpath[200];
	char serverpath[200];

	sprintf(fpath, "/etc/netcop/%s", whichlist);
	sprintf(serverpath, "ftp://localhost/%s", whichlist);

	CURL *curl;
	struct FtpFile file = {fpath, NULL};

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(!curl) { 
		printf("curl_easy_init failed\n");
		return -1;
	}
	
	curl_easy_setopt(curl, CURLOPT_URL, serverpath);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, temp_fwrite);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &file);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	if (res != CURLE_OK) {
		printf("syncing failed at curl_easy_perform\n");
		return -1;
	}
	if(file.stream)
		fclose(file.stream); 
	return 0;
}
size_t temp_fwrite(void *buff,size_t size,size_t n,void *s)
{
	struct FtpFile *fp=(struct FtpFile *)s;
	if (!fp) {
		printf("fp null error\n");
		return 0;
	}
	if(!fp->stream)
		fp->stream=fopen(fp->filename, "wb");
	if(!fp->stream) {
		printf("fp stream null error\n");
		return 0; 
	}
	return fwrite(buff,size,n,fp->stream);
}


