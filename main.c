#include <stdio.h>
#include "defs.h"

#define STR_HELP 	"Wellcome to Tcp Reordering Checker.\n"\
			"To run program use the following format :\n"\
			"\t trc <pcap file>.\n"\
			"With <pcap file> the pcap file to Analyse.\n"


int main(int argc,char** argv){
	printf("starting\n");
	if(argc != 2){
		fprintf(stderr,"ERROR  No pcap file passed!\n");
		printf(STR_HELP);
		return ERR_NO_FILE_PASSED;
	}
	

	return 0;
}
