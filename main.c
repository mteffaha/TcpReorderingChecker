#include <stdio.h>
#include <pcap.h>
#include "defs.h"
#include "dispatcher.h"

// Wellcome message to print
#define STR_HELP 	"Wellcome to Tcp Reordering Checker.\n"\
			"To run program use the following format :\n"\
			"\t trc <pcap file>.\n"\
			"With <pcap file> the pcap file to Analyse.\n"


extern packetEntry* g_entries;
extern packetEntry* g_currentEntries;

int main(int argc,char** argv){
	pcap_t* pFile;// a pointer to the pcap file
	char errbuf[PCAP_ERRBUF_SIZE];// the buffer that will contain the errors return by pcap.
	
	// we Check the parameters
	if(argc != 2){
		fprintf(stderr,"\nERROR!  No pcap file passed!\n");
		printf(STR_HELP);
		return ERR_NO_FILE_PASSED;
	}

	// TODO Check file is readable/reachable


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

	
	// we write the returned entries the csv file
	packetEntry* entry = g_entries;

	while(entry != NULL){
		printf("[SADDR : %x<>DADDR : %x]\n",entry->saddr,entry->daddr);
		entry = entry->next;
	}
	// we clean up the list of entries
	free_Entry(&g_entries);
	free_Entry(&g_currentEntries);

	return 0;
}
