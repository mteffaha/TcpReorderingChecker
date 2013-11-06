#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "defs.h"
#include "dispatcher.h"
#include <stdlib.h>

int id=0; // the packet ID(as read from the pcap file)


packetEntry* g_entries = NULL;		// entries that were recieved 
int initial_reciever_seq = -1;		// the initial recieved sequence number used to calculate the relative sequence number
int initial_sender_seq = -1;		// same as initial_recieved_seq but for the sender
u_int32_t recieverADR = -1;		// the reciever adress used to filter out packets
int expected_seq = -1;			// variable used to store the exepected sequence number at each iteration

void dispatch_handler(u_char* user,const struct pcap_pkthdr* header,const u_char* data){
	struct iphdr ipHeader;
	unsigned int ihl=0; // Internet Header Length


	id++;
	/*
		============================================== Initialisation part
	*/

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

	
	/*
		========================================= Delay detection Part
	*/




	// We get the initial sequence number,and the reciever adresse 
	if(entry->tcpHeader->syn&&entry->tcpHeader->ack){
		initial_reciever_seq = entry->tcpHeader->seq;
		recieverADR = entry->daddr;
	}
	if(entry->tcpHeader->syn && ! entry->tcpHeader->ack){
		initial_sender_seq =entry->tcpHeader->seq;
	}



	// we calculate the length of data (needed to calculate the next sequence number)
	length = ntohs(ipHeader.tot_len)-((ihl*4)+(entry->tcpHeader->doff*4));



	/*	
		We Skip the Three way handshake 

	*/

	if(expected_seq == -1){ // we initialse the first recieved packet to the length of data which happens to be it's sequence number
		expected_seq = length;
	}
	
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

	


	/*
		we filter only the recieved packet since only they, are relative to our probléme
	*/
	if(entry->daddr == recieverADR){ // recieved packet
		if((entry->tcpHeader->seq-initial_reciever_seq) < expected_seq){ // if sequence number earlier (delayed packet)
			// we create a new packetEntry that will be filed with the relative information, once the delayed packet is recieved
			packetEntry* delayedEntry = (packetEntry*)malloc(sizeof(packetEntry)); 
			delayedEntry->delay=id; // the delay stores the id in which the packet should of arrived, 
						// and thus will be used when the actual packet arrive to calculate the delay
			delayedEntry->sequence= expected_seq;
			delayedEntry->next = NULL;
			add_Entry(&g_entries,&delayedEntry);

		}			
		
		expected_seq = (entry->tcpHeader->seq-initial_reciever_seq)+length;
		
		// we go through our list of entries to see if the current packet is a packet we've been looking for
		packetEntry* current = g_entries;
		while(current != NULL){
			if(current->sequence == (entry->tcpHeader->seq-initial_reciever_seq)){ // if it's the case
				// we store it's information in the packetEntry list
				current->delay=id-current->delay;
				current->saddr = entry->saddr;
				current->daddr = entry->daddr;

				current->ID = id;
				current->tcpHeader = entry->tcpHeader;


				if(entry->delay >= 3){
					current->retransmission = 1;
				}else{
					current->retransmission = 0;
				}


			}
			current = current->next;
		}

	}
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
