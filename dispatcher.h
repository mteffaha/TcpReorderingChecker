#ifndef __DISPATCHER_H__
#define __DISPATCHER_H__
#include <pcap.h>

// the dispatcher function that will be passed to the pcap_loop and will recieve the packets one by one
void dispatch_handler(u_char*,const struct pcap_pkthdr*,const u_char*);

#endif
