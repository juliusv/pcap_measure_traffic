/* Simple pcap traffic measurement tool */

#include <pcap.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[])
{
  pcap_t *handle;                 /* Session handle */
  const char *dev;                /* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
  struct bpf_program fp;          /* The compiled filter */
  const char *filter_exp;         /* The filter expression */
  bpf_u_int32 mask;               /* Our netmask */
  bpf_u_int32 net;                /* Our IP */
  struct pcap_pkthdr header;      /* The header that pcap gives us */
  const u_char *packet;           /* The actual packet */
  int capture_duration;           /* How long to capture in seconds */
  time_t begin_time;              /* Capture begin time */
  unsigned long total_bytes = 0;  /* Total bytes seen in packets */

  if (argc != 4) {
    fprintf(stderr,
            "Usage: %s <device> <capture duration> <filter expression>\n",
            argv[0]);
    return(1);
  }

  dev = argv[1];
  capture_duration = atoi(argv[2]);
  filter_exp = argv[3];

  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
      fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }

  /* Open the session in non-promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }

  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
              pcap_geterr(handle));
    return(2);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
              pcap_geterr(handle));
    return(2);
  }

  begin_time = time(NULL);
  while (time(NULL) - begin_time < capture_duration) {
    /* Grab a packet and record its length */
    packet = pcap_next(handle, &header);
    total_bytes += header.len;
  }

  printf("Total bytes: %.2f MB\n", (float)total_bytes / 1024 / 1024);

  /* And close the session */
  pcap_close(handle);
  return(0);
}
