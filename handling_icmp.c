// Created by Susanka on 11/12/2019.

#include "header.h"

int is_icmp(FRAME *frame) {
    FILE *protocols = open_protocols_file();
    char protocol_name[10];
    int protocol_number;

    while (fscanf(protocols, "%d", &protocol_number) != EOF) {
        fscanf(protocols, "%s", protocol_name);

        if (frame->frame_data[23] == protocol_number) {
            if (strcmp(protocol_name, "ICMP") == 0) {
                return 1;
            }
        }
    }

    close_protocols_file(protocols);
    return 0;
}

FRAME** find_only_icmp(FRAME *header, char *protocol, int *size){
    FILE *protocols = open_protocols_file();
    char protocol_name[10];
    int protocol_number;
    FRAME *actual = header;
    int counter = 0;
    (*size) = 0;

    while (actual != NULL) {
        (*size)++;
        actual = actual->next;
    }
    actual = header;
    FRAME **protocol_only = (FRAME **) malloc((*size) * sizeof(FRAME *));

    ////////////////////////////

    for (int i = 0; i < *size; i++) {
        protocol_only[i] = (FRAME *) malloc(sizeof(FRAME));
    }

    while (fscanf(protocols, "%d", &protocol_number) != EOF) {
        fscanf(protocols, "%s", protocol_name);

        if (strcmp(protocol, protocol_name) == 0) {
            break;
        }
    }
    close_port_file(protocols);
    *size = 0;
    counter = 0;

    while (actual != NULL) {
        if (is_ipv4_not_add(actual) && is_icmp(actual)) {
            protocol_only[counter++] = actual;
            (*size)++;
        }

        actual = actual->next;
    }

    return protocol_only;
}

void print_type(FRAME* frame, FILE* output){
    int type = hex_to_dec_1(frame->frame_data, 34 + frame->offset);;
    switch(type){
        case 0:
            fprintf(output, "Typ = Echo reply\n");
            break;
        case 3:
            fprintf(output, "Typ = Destination unreachable\n");
            break;
        case 8:
            fprintf(output, "Typ = Echo\n");
            break;
        case 11:
            fprintf(output, "Typ = Time exceeded\n");
            break;
        default:
            fprintf(output, "Typ = Other (%d)\n", type);
    }
}

void print_duo_icmp(FRAME **protocol_only, int size, FILE *output) {
    IP_ADRESS *ip1s;
    IP_ADRESS *ip1d;
    IP_ADRESS *ip2s;
    IP_ADRESS *ip2d;
    int type1;
    int type2;

    for (int i = 0; i < size - 1; i++) {
        ip1s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip1s->address[a] = protocol_only[i]->frame_data[26 + a];
        }

        ip1d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip1d->address[a] = protocol_only[i]->frame_data[30 + a];
        }
        type1 = hex_to_dec_1(protocol_only[i]->frame_data, 34 + protocol_only[i]->offset);

        if (type1 == 8) {
            //mam echo
            for (int j = i + 1; j < size; j++) {
                ip2s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2s->address[a] = protocol_only[j]->frame_data[26 + a];
                }

                ip2d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2d->address[a] = protocol_only[j]->frame_data[30 + a];
                }
                type2 = hex_to_dec_1(protocol_only[j]->frame_data, 34 + protocol_only[j]->offset);

                if (are_same_comunication(ip1s, ip1d, ip2s, ip2d, 0, 0, 0, 0)) {
                    if(type2 == 0 || type2 == 3 || type2 == 11){
                        fprintf(output,
                                "--------------------------------------------------------------------------------------------\n");
                        fprintf(output, "Echo posielal rámec:\n");
                        print_ipv4_frame(protocol_only[i], output);
                        fprintf(output,
                                "--------------------------------------------------------------------------------------------\n");
                        fprintf(output, "Reply posielal rámec:\n");
                        print_ipv4_frame(protocol_only[j], output);
                        break;
                    }
                }

            }
        }
    }
}

void print_icmp_single(FRAME **protocol_only, int size, FILE *output){
    IP_ADRESS *ip1s;
    IP_ADRESS *ip1d;
    IP_ADRESS *ip2s;
    IP_ADRESS *ip2d;
    int type1;
    int type2;

    fprintf(output,
            "--------------------------------------------------------------------------------------------\n");
    fprintf(output, "Nespárovené:\n");

    for (int i = 0; i < size - 1; i++) {
        ip1s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip1s->address[a] = protocol_only[i]->frame_data[26 + a];
        }

        ip1d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip1d->address[a] = protocol_only[i]->frame_data[30 + a];
        }
        type1 = hex_to_dec_1(protocol_only[i]->frame_data, 34 + protocol_only[i]->offset);

        if (type1 == 8) {
            //mam echo
            for (int j = i + 1; j < size; j++) {
                ip2s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2s->address[a] = protocol_only[j]->frame_data[26 + a];
                }

                ip2d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2d->address[a] = protocol_only[j]->frame_data[30 + a];
                }

                if (are_same_comunication(ip1s, ip1d, ip2s, ip2d, 0, 0, 0, 0)) {
                    break;
                }

                if(j == size - 1){
                    print_ipv4_frame(protocol_only[i], output);
                }

            }
        }
    }
}