#include <pcap.h>


void dispatch_handler(u_char* user,const struct pcap_pkthdr* header,const u_char* data){
	printf("[DISPATCH_HANDLER]Packet Recieved : %s",user);

}
