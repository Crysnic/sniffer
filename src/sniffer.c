#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

static void usage(void) { 
    printf("Usage: sniffer [options]\n");
    printf("-i      specify interface\n");
    printf("-f      specify filter expression\n");
    printf("-h      display this help\n");
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
    char filter_exp[48];               // Filter expression
    struct bpf_program fp;          // Compiled filter expression 
    struct pcap_pkthdr header;      // The header that pcap gives us

    if(argc == 1)
        usage();    
   
    while((opt = getopt(argc, argv, "i:f:h")) != -1) {
        switch(opt) {
            case 'h':
                    usage(); break;
            case 'i':
                    dev = optarg; break;
            case 'f':
                    strcpy(filter_exp, optarg);
                    break;
            case '?':
                    usage();
        }   

}   

if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, toMs, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
     } 

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", 
                filter_exp, pcap_geterr(handle));
        return(2);
    }  
 
     if(pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        return(2);
    }
    
    pcap_next(handle, &header);

    printf("Device: %s\n", dev);
    printf("Data link: %d\n", (pcap_datalink(handle)));
    printf("IP: %d\n", net);
    printf("Mask: %d\n", mask);
    printf("Filter expression: %s\n", filter_exp);
    printf("\nJacked a packet with length of [%d]\n", header.len);

    pcap_close(handle);
    return(0);
}
