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

void print_duo(FRAME **protocol_only, int size, FILE *output) {
    IP_ADRESS *ip1s;
    IP_ADRESS *ip1d;
    IP_ADRESS *ip2s;
    IP_ADRESS *ip2d;
    int port1s;
    int port1d;
    int port2s;
    int port2d;
    int number_of_all = 0;
    int to_be_print_number = 0;

    for (int i = 0; i < size - 1; i++) {
        ip1s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip1s->address[a] = protocol_only[i]->frame_data[26 + a];
        }

        ip1d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip1d->address[a] = protocol_only[i]->frame_data[30 + a];
        }
        port1s = hex_to_dec_1(protocol_only[i]->frame_data, 34 + protocol_only[i]->offset);
        port1d = hex_to_dec_1(protocol_only[i]->frame_data, 36 + protocol_only[i]->offset);

        if (is_syn(protocol_only[i])) {
            for (int j = i + 1; j < size; j++) {
                ip2s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2s->address[a] = protocol_only[j]->frame_data[26 + a];
                }

                ip2d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2d->address[a] = protocol_only[j]->frame_data[30 + a];
                }
                port2s = hex_to_dec_1(protocol_only[j]->frame_data, 34 + protocol_only[j]->offset);
                port2d = hex_to_dec_1(protocol_only[j]->frame_data, 36 + protocol_only[j]->offset);

                if (are_same_comunication(ip1s, ip1d, ip2s, ip2d, port1s, port1d, port2s, port2d)) {
                    if (is_fin(protocol_only[j])) {
                        fprintf(output, "Prvá úplná komunikácia je ohraničená:\n\n");
                        fprintf(output, "Prvým SYN packetom:\n");
                        print_ipv4_frame(protocol_only[i], output);
                        to_be_print_number++;
                    }
                    number_of_all++;
                }
                if (are_same_comunication_ack(ip1s, ip1d, ip2s, ip2d, port1s, port1d, port2s, port2d)) {
                    number_of_all++;
                }

            }
            for (int j = i + 1; j < size; j++) {
                ip2s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2s->address[a] = protocol_only[j]->frame_data[26 + a];
                }

                ip2d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
                for (int a = 0; a < 4; a++) {
                    ip2d->address[a] = protocol_only[j]->frame_data[30 + a];
                }
                port2s = hex_to_dec_1(protocol_only[j]->frame_data, 34 + protocol_only[j]->offset);
                port2d = hex_to_dec_1(protocol_only[j]->frame_data, 36 + protocol_only[j]->offset);

                if (are_same_comunication(ip1s, ip1d, ip2s, ip2d, port1s, port1d, port2s, port2d) ||
                    are_same_comunication_ack(ip1s, ip1d, ip2s, ip2d, port1s, port1d, port2s, port2d)) {

                    if ((number_of_all < 20 || to_be_print_number < 10 || to_be_print_number > number_of_all - 10) &&
                        is_fin(protocol_only[j]) == 0) {
                        print_ipv4_frame(protocol_only[j], output);
                    }
                    to_be_print_number++;

                    if (is_fin(protocol_only[j])) {
                        fprintf(output, "\n\nPosledným FIN packetom:\n");
                        print_ipv4_frame(protocol_only[j], output);
                        fprintf(output,
                                "--------------------------------------------------------------------------------------------\n");
                        return;
                    }
                }
            }
        }
    }
}