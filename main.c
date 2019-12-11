#include "header.h"

int main() {
    FRAME* list_of_frames = create_linked_list("trace-20.pcap");
    FRAME** arp_duo = (FRAME**)malloc(2 * sizeof(FRAME*));
    IP_ADRESS* list_of_adresses = NULL;
    FILE* output = open_txt_file();
    FRAME** http_only = NULL;
    int size = 0;

    //print_linked_list(list_of_frames, output, &list_of_adresses, arp_duo);
    http_only = filtre_protocol(list_of_frames, "HTTP", &size);
    //print_protocol_array(http_only, size, output);
    print_first_full(http_only, size, output);
    print_first_not_full(http_only, size, output);

    close_txt_file(output);
    return 0;
}