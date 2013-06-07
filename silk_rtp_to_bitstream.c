#include <pcap.h>
#include <stdio.h>

void dispatcher_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

int main(int argc, char **argv) {
	pcap_t* descr;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc != 2) {
		printf("Usage error.\n");
		return -1;
	}

	if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL) {
		printf("Error opening file.\n");
		return -1;
	}

	pcap_loop(descr, 0, dispatcher_handler, NULL);

	return 0;
}


void dispatcher_handler(u_char* temp1, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	u_int i = 0;

	// TODO: pass output bit file name as argument
	const char *bitOutFileName = "silk.bit"; // SILK bitstream
	FILE* bitOutFile = fopen(bitOutFileName, "ab"); // append to binary file
	if (bitOutFile == NULL) {
		printf("Error: could not open output file %s\n", bitOutFileName);
		return;
	}
	else {
		printf("Output file %s opened successfully\n", bitOutFileName);
	}

	// packet timestamp
	printf("%ld:%ld ", header->ts.tv_sec, header->ts.tv_usec);

	long payload_len = header->len - 56;

	// Payload length
	printf("Length: %ld\n", payload_len);

	// print the payload length as hex
	printf("%.4x ", payload_len);
	fwrite(&payload_len, sizeof(char), 2, bitOutFile);

	fwrite(&pkt_data[56], sizeof(char), payload_len, bitOutFile);

	fclose(bitOutFile);
	printf("\n\n");
}
