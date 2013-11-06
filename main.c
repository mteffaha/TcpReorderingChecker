#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"
#include "dispatcher.h"

#define MAX_WRITE_TRIES 99
// Wellcome message to print
#define STR_HELP 	"Wellcome to Tcp Reordering Checker.\n"\
			"To run program use the following format :\n"\
			"\t trc <pcap file>.\n"\
			"With <pcap file> the pcap file to Analyse.\n"


extern packetEntry* g_entries;

int main(int argc,char** argv){
	pcap_t* pFile;// a pointer to the pcap file
	char errbuf[PCAP_ERRBUF_SIZE];// the buffer that will contain the errors return by pcap.
	char* outputfile=(char*) malloc(sizeof(char)*(strlen(argv[1])+7)); // the output file containes the name of the original file with the extension csv added	
	FILE* outFl = NULL;
	
	// we Check the parameters
	if(argc != 2){
		fprintf(stderr,"\nERROR!  No pcap file passed!\n");
		printf(STR_HELP);
		return ERR_NO_FILE_PASSED;
	}

	// TODO Check file is readable/reachable
	if(access(argv[1],F_OK&R_OK) == -1){
		fprintf(stderr,"\nERROR! %s is not accessible, Check that the file exists and that read permesison are granted\n",argv[1]);
		return ERR_UNABLE_TO_OPEN_FILE;
	}

	// we check that we can write
	sprintf(outputfile,"%s.csv",argv[1]);
	int alternative = 1; // a number to append to the file name in case a similar file exists
	while(access(outputfile,F_OK&W_OK) != -1){
		sprintf(outputfile,"%s_%d.csv",argv[1],alternative);
		alternative++;
		if(alternative > MAX_WRITE_TRIES){
			fprintf(stderr,"\nERROR!! unable to write output file , Check that the folder has the write permission granted");
			return ERR_UNABLE_TO_WRITE_FILE;
		}
	}
	

	// We open the pcap dump file
	if((pFile = pcap_open_offline(argv[1],errbuf)) == NULL){
		fprintf(stderr,"\nERROR! Unable to open the pcap file : %s\n",argv[1]);
		return ERR_UNABLE_TO_OPEN_FILE;
	}

	// we start the pcap_loop , which will dispatch the packets one by one to our handler function		
	if(pcap_loop(pFile,0,dispatch_handler,NULL)== -1){
		fprintf(stderr,"\nERROR! pcap_loop Ended with the following error:[%s]\n",errbuf); 
		return ERR_PCAP_LOOP;
	}
	// we open our output file for writing
	outFl = fopen(outputfile,"w");
	
	// we write the returned entries the csv file
	packetEntry* entry = g_entries;

	while(entry != NULL){
		
		fprintf(outFl,"%d,%d,%d\n",entry->ID,entry->delay,(entry->delay>=3&&entry->ID!=0)?1:0);
		entry = entry->next;
	}

	fclose(outFl);
	// we clean up the list of entries
	free_Entry(&g_entries);

	return 0;
}
