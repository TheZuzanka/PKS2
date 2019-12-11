#include "header.h"

int main() {
    FRAME* list_of_frames = create_linked_list("trace-26.pcap");
    IP_ADRESS* list_of_adresses = NULL;
    FILE* output = open_txt_file();
    FRAME** protocol_only = NULL;
    int size = 0;

    int option;


    while(1){
        printf("--------------------------------------------------------------------------\n");
        printf("Vypis vsetkych komunikacii do suboru: 1\n");
        printf("Vypis iba HTTP: 2\n");
        printf("Vypis iba HTTPS: 3\n");
        printf("Vypis iba TELNET: 4\n");
        printf("Vypis iba SSH: 5\n");
        printf("Vypis iba FTP-riadiace: 6\n");
        printf("Vypis iba FTP-datove: 7\n");
        printf("Vypis iba TFTP: 8\n");
        printf("Vypis iba ICMP: 9\n");
        printf("Vypis iba ARP: 10\n");
        printf("Ukoncit: 11\n");

        scanf("%d", &option);

        printf("--------------------------------------------------------------------------\n");

        switch (option){
            case ALL:
                print_linked_list(list_of_frames, output, &list_of_adresses, NULL);
                break;
            case HTTP:
                free_protocol_only(protocol_only, &size);
                protocol_only = filtre_protocol(list_of_frames, "HTTP", &size);
                print_first_full(protocol_only, size, output);
                print_first_not_full(protocol_only, size, output);
                break;
            case HTTPS:
                free_protocol_only(protocol_only, &size);
                protocol_only = filtre_protocol(list_of_frames, "HTTPS", &size);
                print_first_full(protocol_only, size, output);
                print_first_not_full(protocol_only, size, output);
                break;
            case TELNET:
                free_protocol_only(protocol_only, &size);
                protocol_only = filtre_protocol(list_of_frames, "TELNET", &size);
                print_first_full(protocol_only, size, output);
                print_first_not_full(protocol_only, size, output);
                break;
            case SSH:
                free_protocol_only(protocol_only, &size);
                protocol_only = filtre_protocol(list_of_frames, "SSH", &size);
                print_first_full(protocol_only, size, output);
                print_first_not_full(protocol_only, size, output);
                break;

            case FTP_R:
                free_protocol_only(protocol_only, &size);
                protocol_only = filtre_protocol(list_of_frames, "FTPC", &size);
                print_first_full(protocol_only, size, output);
                print_first_not_full(protocol_only, size, output);
                break;

            case FTP_D:
                free_protocol_only(protocol_only, &size);
                protocol_only = filtre_protocol(list_of_frames, "FTPD", &size);
                print_first_full(protocol_only, size, output);
                print_first_not_full(protocol_only, size, output);
                break;

            case TFTP:
                break;

            case ICMP:
                free_protocol_only(protocol_only, &size);
                protocol_only = find_only_icmp(list_of_frames, "ICMP", &size);
                print_duo_icmp(protocol_only, size, output);
                print_icmp_single(protocol_only, size, output);
                break;

            case ARP:
                break;

            case EXIT:
                close_txt_file(output);
                return 1;

        }
    }
}