#include <pcap.h>
#include <stdio.h>

// 12 B RTP, 8 B UDP, 20 B IP, 14 B Ethernet, 2 B payload length
#define HEADER_LEN 56

void dispatcher_handler(u_char*, const struct pcap_pkthdr*, const u_char*);

int main(int argc, char **argv) {
	pcap_t* descr;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc != 3) {
		printf("Usage error. ./silk_rtp_to_bitstream <input pcap> <output .bit>\n");
		return -1;
	}

	if ((descr = pcap_open_offline(argv[1], errbuf)) == NULL) {
		printf("Error opening file.\n");
		return -1;
	}

	const char *bitOutFileName = argv[2]; // SILK bitstream for output
	FILE* bitOutFile = fopen(bitOutFileName, "ab"); // append to binary file
	if (bitOutFile == NULL) {
		printf("Error: could not open output file %s\n", bitOutFileName);
		return;
	}
	else {
		printf("Output file %s opened successfully\n", bitOutFileName);
	}

	// Insert the magic number
	// 23 21 53 49 4c 4b 5f 56  33
        long magic_number_length = 9;
	char magic_number[] = "#!SILK_V3";
	fwrite(magic_number, sizeof(char), magic_number_length, bitOutFile);

	pcap_loop(descr, 0, dispatcher_handler, (u_char*)bitOutFile);

	fclose(bitOutFile);
	return 0;
}


void dispatcher_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	u_int i = 0;

	FILE* bitOutFile = (FILE *)args;

	// packet timestamp
	printf("%ld:%ld ", header->ts.tv_sec, header->ts.tv_usec);

	long payload_len = header->len - HEADER_LEN;

	// Payload length
	printf("Length: %ld\n", payload_len);

	// print the payload length as hex
	printf("%.4x ", payload_len);
	fwrite(&payload_len, sizeof(char), 2, bitOutFile);

	// print payload
	fwrite(&pkt_data[56], sizeof(char), payload_len, bitOutFile);

	printf("\n\n");
}
