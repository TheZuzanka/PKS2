// Created by Susanka on 24/11/2019.

#include "header.h"

void print_frame_length(FRAME *frame, FILE *output) {
    int length;

    if (frame->frame_wrapper->len < 60) {
        length = 64;
    } else {
        length = frame->frame_wrapper->len + 4;
    }

    fprintf(output, "Velkost ramca z pcap API =  %dB\n", frame->frame_wrapper->caplen);
    fprintf(output, "Velkost ramca prenasaneho po mediu = %dB\n", length);
}

int hex_to_dec(const u_char *frame_data, int starting_index) {
    int i = 0, pow = 1;
    int number = 0;
    for (i = 0; i < 4; i++) {
        int val = (int) frame_data[starting_index - (i / 2)];
        if (i % 2 == 0) {
            number += ((val % 16) * pow);
        } else {
            number += ((int) (val / 16) * pow);
        }
        pow *= 16;
    }
    return number;
}

void print_mac_addresses(const u_char *pcap_pkt_data, FILE *output) {
    fprintf(output, "Cielova MAC adresa = ");
    for (int i = 0; i <= 5; i++) {
        fprintf(output, "%.2X ", pcap_pkt_data[i]);
    }
    fprintf(output, "\n");


    fprintf(output, "Zdrojova MAC adresa = ");
    for (int i = 6; i <= 11; i++) {
        fprintf(output, "%.2X ", pcap_pkt_data[i]);
    }
    fprintf(output, "\n");
}

int hex_to_dec_1(const u_char *frame_data, int index) {
    int pow = 1;
    int number = 0;
    for (int i = 0; i < 2; i++) {
        int val = (int) frame_data[index - (i / 2)];
        if (i % 2 == 0) {
            number += ((val % 16) * pow);
        } else {
            number += ((int) (val / 16) * pow);
        }
        pow *= 16;
    }

    return number;
}

void eth_or_802(FRAME *frame, FILE *output) {
    FILE *ieee_file = open_ieee_file();
    int number;
    int found = 0;
    char ieee_podcategory[10];

    fprintf(output, "Typ = ");
    if (hex_to_dec(frame->frame_data, 13) >= 1500) {
        fprintf(output, "Ethernet II\n");
    } else {
        while (fscanf(ieee_file, "%d", &number) != EOF) {
            fscanf(ieee_file, "%s", ieee_podcategory);
            if (hex_to_dec_1(frame->frame_data, 14) == number) {
                fprintf(output, "%s\n", ieee_podcategory);
                //LLC a LLC SNAP vnorene protokoly
                found = 1;
            }
        }
        if (found == 0){
            fprintf(output, "IEEE - LLC\n");
        }
    }

    close_ieee_file(ieee_file);
}

void print_data(const u_char *frame_data, int length, FILE *output) {
    fprintf(output, "Datove pole \n\n");
    for (int i = 1; i < length + 1; i++) {
        fprintf(output, "%.2X ", frame_data[i - 1]);
        if ((i > 0) && ((i % 8) == 0)) {
            fprintf(output, "  ");
        }
        if ((i > 0) && ((i % 16) == 0)) {
            fprintf(output, "\n");
        }
    }
    fprintf(output, "\n");
}

void print_frame_info(FRAME *frame, FILE *output) {
    fprintf(output, "--------------------------------------------------------------------------------------------\n");
    fprintf(output, "Cislo ramca = %d\n", frame->frame_number);
    print_frame_length(frame, output);
    eth_or_802(frame, output);
    print_mac_addresses(frame->frame_data, output);
}

void print_ip_sc_dst(FRAME *frame, FILE *output) {
    fprintf(output, "Zdrojova IP adresa = ");
    IP_ADRESS *my_source_address = create_ip_struct(frame, 26);
    print_ip_adress(my_source_address, output);
    free(my_source_address);

    fprintf(output, "Cielova IP adresa = ");
    IP_ADRESS *my_destin_address = create_ip_struct(frame, 30);
    print_ip_adress(my_destin_address, output);
}

/*void print_LLC_sub(FRAME* frame){
    if(hex_to_dec_1(frame->frame_data, 15) == 99)
}

void print_LLC_SNAP_sub(FRAME* frame){
    //
}*/

FRAME** filtre_protocol(FRAME* header, char* protocol, int* size){
    FILE* ports = open_port_file();
    char port_name[10];
    int port_number;
    FRAME* actual = header;
    int counter = 0;
    (*size) = 0;

    while(actual != NULL){
        (*size)++;
        actual = actual->next;
    }
    actual = header;
    FRAME** protocol_only = (FRAME**)malloc((*size) * sizeof(FRAME*));

    ////////////////////////////

    for(int i = 0; i < *size; i++){
        protocol_only[i] = (FRAME*)malloc(sizeof(FRAME));
    }

    while(fscanf(ports, "%d", &port_number) != EOF){
        fscanf(ports, "%s", port_name);

        if(strcmp(protocol, port_name) == 0){
            break;
        }
    }
    close_port_file(ports);
    *size = 0;
    counter = 0;

    while(actual != NULL){
        int source_port = hex_to_dec(actual->frame_data, 35 + actual->offset);
        int dest_port = hex_to_dec(actual->frame_data, 37 + actual->offset);

        if(source_port == port_number || dest_port == port_number){
            protocol_only[counter++] = actual;
            (*size)++;
        }

        actual = actual->next;
    }

    return protocol_only;
}

void print_first_full(FRAME** protocol_only, int size, FILE* output){
    IP_ADRESS* ip1s;
    IP_ADRESS* ip1d;
    IP_ADRESS* ip2s;
    IP_ADRESS* ip2d;
    int port1s;
    int port1d;
    int port2s;
    int port2d;

    for(int i = 0; i < size - 1; i++){
        ip1s = (IP_ADRESS*)malloc(sizeof(IP_ADRESS));
        for(int a = 0; a < 4; a++){
            ip1s->address[a] = protocol_only[i]->frame_data[26 + a];
        }
        port1s = protocol_only[i]->frame_data[23];

        ip1d = (IP_ADRESS*)malloc(sizeof(IP_ADRESS));
        for(int a = 0; a < 4; a++){
            ip1d->address[a] = protocol_only[i]->frame_data[30 + a];
        }
        port1s =  hex_to_dec_1(protocol_only[i]->frame_data, 34);
        port1d = hex_to_dec_1(protocol_only[i]->frame_data, 36);

        if( is_syn(protocol_only[i]) ){
            for(int j = 0; j < size; j++){
                ip2s = (IP_ADRESS*)malloc(sizeof(IP_ADRESS));
                for(int a = 0; a < 4; a++){
                    ip2s->address[a] = protocol_only[j]->frame_data[26 + a];
                }

                ip2d = (IP_ADRESS*)malloc(sizeof(IP_ADRESS));
                for(int a = 0; a < 4; a++){
                    ip2d->address[a] = protocol_only[j]->frame_data[30 + a];
                }
                port2s =  hex_to_dec_1(protocol_only[j]->frame_data, 34);
                port2d = hex_to_dec_1(protocol_only[j]->frame_data, 36);

                if(are_ip_same(ip2d, ip1s) && port2d == port1s && is_fin(protocol_only[j])){
                    fprintf(output, "Uplna komunikacia medzi %d a %d ramcami", protocol_only[i]->frame_number, protocol_only[j]->frame_number);
                    return;
                }
            }
        }
    }
}

/*void print_TCP(FRAME* header, char* protocol){
    //
}*/

