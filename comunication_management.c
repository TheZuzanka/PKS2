// Created by Susanka on 24/11/2019.

#include "header.h"

void free_protocol_only(FRAME** protocol_only, int* size){
    for(int i = 0; i < *size; i++){
        free(protocol_only[i]);
    }
    free(protocol_only);
    *size = 0;
}

FRAME* create_element(int frame_number, struct pcap_pkthdr *frame_wrapper, u_char *frame_data){
    FRAME *new_element = (FRAME*)malloc(sizeof(FRAME));
    new_element->frame_wrapper = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr));
    new_element->frame_data = (u_char*)malloc(frame_wrapper->caplen * sizeof(u_char));
    new_element->next = (FRAME*)malloc(sizeof(FRAME));

    memcpy(new_element->frame_wrapper, frame_wrapper, sizeof(struct pcap_pkthdr));
    memcpy(new_element->frame_data, frame_data, frame_wrapper->caplen * sizeof(u_char));
    new_element->frame_number = frame_number;
    new_element->offset = 0;
    new_element->next = NULL;

    return new_element;
}

FRAME* create_linked_list(char* file_name){
    FRAME *list_of_frames = NULL;
    FRAME *actual = list_of_frames;
    struct pcap_pkthdr *pcap_pkthdr = NULL;
    u_char *pcap_pkt_data = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *source_file = open_pcap_file(file_name, error_buffer);
    int frame_number = 0;

    while (pcap_next_ex(source_file, &pcap_pkthdr, &pcap_pkt_data) >= 0) {
        frame_number++;
        FRAME *new_element = create_element(frame_number, pcap_pkthdr, pcap_pkt_data);

        if(list_of_frames == NULL){
            list_of_frames = new_element;
            actual = new_element;
        }
        else{
            actual->next = new_element;
            actual = actual->next;
        }
    }

    free(pcap_pkthdr);
    free(pcap_pkt_data);

    close_pcap_file(source_file, file_name);
    return list_of_frames;
}

void print_linked_list(FRAME *header, FILE *output, IP_ADRESS** ip_adresses, FRAME** arp_duo){
    FRAME* actual = header;
    FILE* protocols = open_protocols_file();

    while(actual != NULL){
        if(is_ipv4(actual, ip_adresses)){
            print_ipv4_frame(actual, output);
        }
        else if(is_arp(actual)){
            print_arp_frames(actual, output, arp_duo);
        }
        else{
            print_frame_info(actual, output);
            print_data(actual->frame_data, actual->frame_wrapper->caplen, output);
        }

        actual = actual->next;
    }

    if(header != NULL){
        fprintf(output, "--------------------------------------------------------------------------------------------\n");
        fprintf(output, "IP adresy vysielajucich uzlov:\n");
        print_all_ip_adresses(*ip_adresses, output);
        fprintf(output, "Najviac (%d packetov) odoslala ", get_max_packets(*ip_adresses));
        print_ip_adress(sent_max_packets(*ip_adresses), output);
    }

    close_protocols_file(protocols);
}