silk_rtp_to_bitstream
=====================

Converts a SILK RTP stream into a SILK binary file for decoding

BUILD

gcc silk_rtp_to_bitstream.c -lpcap -o silk_rtp_to_bitstream


USE

./silk_rtp_to_bitstream <input pcap> <output .bit>

The output .bit file can then be converted into PCM with SILK SDK, e.g.:

./decoder silk.bit silk_PCM.raw

Then convert into WAV with:

sox -V -t raw -b 16 -e signed-integer -r 24000 silk_PCM.raw silk.wav
