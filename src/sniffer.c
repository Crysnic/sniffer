#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
        const u_char* packet)
{ 
    static int count = 1;
    printf("Packet number [%d], with length: %d\n", count++, pkthdr->len);
}

static void usage(void) { 
    printf("Usage: sniffer [options]\n");
    printf("-i      specify interface\n");
    printf("-f      specify filter expression\n");
    printf("-h      display this help\n");
    printf("-u      set user id\n");
    printf("-g      set group id\n");
    exit(1);
}

int main(int argc, char *argv[])

{ 
    short opt = 0;
    char *dev;                      // The device to sniff on
    pcap_t *handle;                 // Session handle
    int toMs = 1000;                // Timeout, in milliseconds
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string
    bpf_u_int32 mask = 0;           // Netmask of sniffing device
    bpf_u_int32 net = 0;            // IP of sniffing device
    char filter_exp[48];            // Filter expression
    struct bpf_program fp;          // Compiled filter expression 

    if(argc == 1)
        usage();    
   
    while((opt = getopt(argc, argv, "i:f:hu:g:")) != -1) {
        switch(opt) {
            case 'h':
                    usage(); break;
            case 'i':
                    dev = optarg; break;
            case 'f':
                    strcpy(filter_exp, optarg); break;
            case 'u':
                    setuid(atoi(optarg)); break;
            case 'g':
                    setgid(atoi(optarg)); break;
            case '?':
                    usage();
          }   
    }     

    if(pcap_lookupnet(dev, &net, &mask, errbuf) < 0){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
    } 

    handle = pcap_open_live(dev, BUFSIZ, 1, toMs, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(1);
     } 

    if(pcap_compile(handle, &fp, filter_exp, 0, net) < 0){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", 
                filter_exp, pcap_geterr(handle));
        return(1);
    }  
 
     if(pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        return(1);
    } 
    
    printf("Starting...\n");   
    pcap_loop(handle, -1, callback, NULL);
    pcap_close(handle);
    return(0);
}
