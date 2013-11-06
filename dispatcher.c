#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "defs.h"
#include "dispatcher.h"
#include <stdlib.h>

int id=0;


packetEntry* g_entries = NULL;		// entries that were recieved 
packetEntry* g_currentEntries=NULL; 	// entries that are currently being handled  by the dispatcher
packetEntry* g_saveEntries=NULL;	// entries that will be saved on the csv	
int initial_reciever_seq = -1;
int initial_sender_seq = -1;
u_int32_t recieverADR = -1;
int expected_seq = -1;

void dispatch_handler(u_char* user,const struct pcap_pkthdr* header,const u_char* data){
	struct iphdr ipHeader;
	unsigned int ihl=0; // Internet Header Length
	packetEntry* entry = (packetEntry*) malloc(sizeof(packetEntry));
	// We Fetch the field type located in the last 2 bytes of the ethernet layer
	u_int16_t type;
	memcpy(&type,data+12,2);
	int length =-1;

	// We check if this frame containt an IPv4 Packet.
	type=ntohs(type);
	if(!type == 0x800){ // Not IPv4 Packet (does not concerne us).
		return;// we skip to the next frame
	}

	// We start by copying the ip header (! notice we ignore the first 14 bytes since they belong to the ethernet frame header)
	memcpy(&ipHeader,data+14,sizeof(struct iphdr));
	// we fetch the ihl + other attributes
	memcpy(&ihl,data+14,sizeof(unsigned int)); // we get the first 16bits
	// we filter out the ihl
	ihl = ntohl(ihl);
	ihl = ihl & 0x0F000000;
	ihl = ihl>>24;
	// We fill the entry
	entry->saddr = ntohl(ipHeader.saddr);
	entry->daddr = ntohl(ipHeader.daddr);
	entry->next = NULL;

	//we fetch the tcp header
	entry->tcpHeader =(struct tcphdr*) malloc(sizeof(struct tcphdr));
	memcpy(entry->tcpHeader,data+14+(ihl*4),sizeof(struct tcphdr));
	// we convert to host byte order
	entry->tcpHeader->source = ntohs(entry->tcpHeader->source);
	entry->tcpHeader->dest = ntohs(entry->tcpHeader->dest);
	entry->tcpHeader->seq = ntohl(entry->tcpHeader->seq);
	entry->tcpHeader->ack_seq = ntohl(entry->tcpHeader->ack_seq);

	entry->tcpHeader->window = ntohs(entry->tcpHeader->window);
	entry->tcpHeader->check = ntohs(entry->tcpHeader->check);
	entry->tcpHeader->urg_ptr = ntohs(entry->tcpHeader->urg_ptr);
	
	// We get the initial sequence number,and the reciever adresse 
	if(entry->tcpHeader->syn&&entry->tcpHeader->ack){
		initial_reciever_seq = entry->tcpHeader->seq;
		recieverADR = entry->daddr;
	}
	if(entry->tcpHeader->syn && ! entry->tcpHeader->ack){
		initial_sender_seq =entry->tcpHeader->seq;
	}
	length = ntohs(ipHeader.tot_len)-((ihl*4)+(entry->tcpHeader->doff*4));

	if(entry->daddr == recieverADR){ // sent packet
	// we remove packets that does not contain client data (Syn , RST, FIN)
	if((entry->tcpHeader->seq-initial_reciever_seq)== 0 || (entry->tcpHeader->seq-initial_reciever_seq)==1){ // we skip the three way handshake
		free(entry);
		return;
	}
	}else{
	if((entry->tcpHeader->seq-initial_sender_seq)== 0 || (entry->tcpHeader->seq-initial_sender_seq)==1){ // we skip the three way handshake
		free(entry);
		return;
	}

	
	}
	if(entry->daddr == recieverADR){ // sent packet
	if((entry->tcpHeader->seq-initial_reciever_seq) != expected_seq){
		printf("$");
	}else{
		printf("-");
	}
		
	printf("<%d,%d,%d>[IHL:%d,IdSrc:%x,IpDest:%x,",(entry->tcpHeader->seq-initial_sender_seq),id,length,ihl,entry->saddr,entry->daddr);
	printf("SourcePort:%d,",entry->tcpHeader->source);
	printf("DestPort:%d,",entry->tcpHeader->dest);
	printf("DataOffset:%d,",entry->tcpHeader->doff);
	printf("(ACK:%d,SYN:%d)",entry->tcpHeader->ack,entry->tcpHeader->syn);
	printf("Sequence:%d,",(entry->tcpHeader->seq-initial_reciever_seq));
	printf("Acknowledgement:%d,",(entry->tcpHeader->ack_seq-initial_sender_seq));
	printf("Window:%d,",entry->tcpHeader->window);
		
	printf(",Length:%d]\n",length);
	
	
	}
	else{ // recieved packet
	expected_seq = (entry->tcpHeader->ack_seq-initial_reciever_seq);
	printf("[Expected: %d,id:%d]",expected_seq,id);	
	printf("[IHL:%d,IdSrc:%x,IpDest:%x,",ihl,entry->saddr,entry->daddr);
	printf("SourcePort:%d,",entry->tcpHeader->source);
	printf("DestPort:%d,",entry->tcpHeader->dest);
	printf("DataOffset:%d,",entry->tcpHeader->doff);
	printf("(ACK:%d,SYN:%d)",entry->tcpHeader->ack,entry->tcpHeader->syn);
	printf("Sequence:%d,",(entry->tcpHeader->seq-initial_sender_seq));
	printf("Acknowledgement:%d,",(entry->tcpHeader->ack_seq-initial_reciever_seq));
	printf("Window:%d,",entry->tcpHeader->window);
		
	printf(",Length:%d]\n",length);
	}

	// We check for reordering

	//add_Entry(&g_currentEntries,&entry);
	
	id++;
	
}


void add_Entry(packetEntry** root,packetEntry** newEntry){
	packetEntry* entry = *root;
	if(*root == NULL){ // First Entry
		*root = *newEntry;  // We replace the root by the new Entry
		return; // done
	}

	
	// we loop through all the elements until we arrive to last element (where our newEntry will be attached)
	while( entry->next != NULL){
		entry = entry->next;		
	}
	//we attache our new Entry
	entry->next = *newEntry;
	
}
void free_Entry(packetEntry** root){
	packetEntry* previous; // Parent Entry
	packetEntry* entry; // Child entry

	entry = *root; // we set our first entry to our root element

	// First we fetch the child , then we free the parent , and set the child as the new parent
	// we repeat until the last child (ie no children)
	while(entry != NULL){
		previous = entry;
		entry = previous->next;
		free(previous);
	}
	
}
