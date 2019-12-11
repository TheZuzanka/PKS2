// Created by Susanka on 11/12/2019.

#include "header.h"

int find_port_number_tftp(){
    FILE *ports = open_port_file();
    char port_name[10];
    int port_number;


    while (fscanf(ports, "%d", &port_number) != EOF) {
        fscanf(ports, "%s", port_name);

        if (strcmp("TFTP", port_name) == 0) {
            return  port_number;
        }
    }
    close_port_file(ports);
}

int is_tftp(FRAME *frame, int port_number, int protocol_num) {

    if (is_ipv4_not_add(frame) && is_udp(frame, protocol_num)) {
        int dest_port = hex_to_dec(frame->frame_data, 37 + frame->offset);

        if (dest_port == port_number) {
            return 1;
        }
    }

    return 0;
}

FRAME *find_first_tftp(FRAME *list_of_packets, int port_num, int protocol_num) {
    FRAME *actual = list_of_packets;

    while (actual != NULL) {
        if (is_tftp(actual, port_num, protocol_num)) {
            return actual;
        }
        actual = actual->next;
    }

    return NULL;
}

FRAME *find_first_reply(FRAME *list_of_packets, FRAME *first, int protocol_num) {
    FRAME *actual = first->next;
    IP_ADRESS *ip1s;
    IP_ADRESS *ip1d;
    IP_ADRESS *ip2s;
    IP_ADRESS *ip2d;
    int port1s = hex_to_dec(first->frame_data, 35 + first->offset);
    int port1d = hex_to_dec(first->frame_data, 37 + first->offset);
    int port2s;
    int port2d;

    ip1s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
    for (int a = 0; a < 4; a++) {
        ip1s->address[a] = first->frame_data[26 + a];
    }

    ip1d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
    for (int a = 0; a < 4; a++) {
        ip1d->address[a] = first->frame_data[30 + a];
    }

    while (actual != NULL) {
        ip2s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip2s->address[a] = actual->frame_data[26 + a];
        }

        ip2d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
        for (int a = 0; a < 4; a++) {
            ip2d->address[a] = actual->frame_data[30 + a];
        }
        port2s = hex_to_dec(actual->frame_data, 35 + actual->offset);
        port2d = hex_to_dec(actual->frame_data, 37 + actual->offset);

        if (is_ipv4_not_add(actual) && is_udp(actual, protocol_num) && are_same_comunication(ip1s, ip1d, ip2s, ip2d, port1s, 0, 0, port2d)) {
            return actual;
        }
        actual = actual->next;
    }
}

int find_protocol_number_udp(){
    FILE *protocols = open_protocols_file();
    char protocol_name[10];
    int protocol_number;


    while (fscanf(protocols, "%d", &protocol_number) != EOF) {
        fscanf(protocols, "%s", protocol_name);

        if (strcmp("UDP", protocol_name) == 0) {
            return  protocol_number;
        }
    }
    close_protocols_file(protocols);
}

int is_udp(FRAME *frame, int protocol_num) {
    if (frame->frame_data[23] == protocol_num) {
        return 1;
    }
    return 0;
}

void print_tftp(FRAME *list_of_packets, FILE* output) {
    FRAME *actual = list_of_packets;
    FRAME *first = NULL;
    FRAME *reply = NULL;
    IP_ADRESS *ip1s;
    IP_ADRESS *ip1d;
    IP_ADRESS *ip2s;
    IP_ADRESS *ip2d;
    int port1s;
    int port1d;
    int port2s;
    int port2d;
    int port_num = find_port_number_tftp();
    int protocol_num = find_protocol_number_udp();

    first = find_first_tftp(list_of_packets, port_num, protocol_num);
    if(first == NULL){
        fprintf(output, "Žiadne komunikácie TFTP\n");
        return;
    }

    ip1s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
    for (int a = 0; a < 4; a++) {
        ip1s->address[a] = first->frame_data[26 + a];
    }

    ip1d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
    for (int a = 0; a < 4; a++) {
        ip1d->address[a] = first->frame_data[30 + a];
    }
    port1s = hex_to_dec(first->frame_data, 35 + first->offset);

    reply = find_first_reply(list_of_packets, first, protocol_num);
    port1d = hex_to_dec(reply->frame_data, 35 + first->offset);

    fprintf(output, "Prvý packet TFTP:\n");
    print_ipv4_frame(first, output);


    while (actual != NULL) {
        if(is_udp(actual, protocol_num)){
            ip2s = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
            for (int a = 0; a < 4; a++) {
                ip2s->address[a] = actual->frame_data[26 + a];
            }

            ip2d = (IP_ADRESS *) malloc(sizeof(IP_ADRESS));
            for (int a = 0; a < 4; a++) {
                ip2d->address[a] = actual->frame_data[30 + a];
            }
            port2s = hex_to_dec(actual->frame_data, 35 + actual->offset);
            port2d = hex_to_dec(actual->frame_data, 37 + actual->offset);

            if (are_same_comunication(ip1s, ip1d, ip2s, ip2d, port1s, port1d, port2s, port2d)) {
                fprintf(output, "--------------------------------------------------------------------------------------------\n");
                print_ipv4_frame(actual, output);
            }
            else if(are_same_comunication_ack(ip1s, ip1d, ip2s, ip2d, port1s, port1d, port2s, port2d)) {
                fprintf(output, "--------------------------------------------------------------------------------------------\n");
                print_ipv4_frame(actual, output);
            }
        }

        actual = actual->next;
    }
}

