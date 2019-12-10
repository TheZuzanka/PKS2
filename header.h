// Created by Susanka on 19/11/2019.

#ifndef PKS_ANALYZER_BASE_HEADER_H
#define PKS_ANALYZER_BASE_HEADER_H
#endif //PKS_ANALYZER_BASE_HEADER_H

#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

typedef struct frame{
    int frame_number;
    struct pcap_pkthdr *frame_wrapper;
    u_char *frame_data;
    struct frame *next;
    int offset;
}FRAME;

typedef struct ip_adress{
    int packet_sent;
    u_char address[4];
    struct ip_adress *next;
}IP_ADRESS;

//from file_management.c
pcap_t *open_pcap_file(char *file_name, char *error_buffer);
void close_pcap_file(pcap_t *file, char *file_name);
FILE* open_txt_file();
void close_txt_file(FILE* txt_file);
FILE* open_protocols_file();
void close_protocols_file(FILE* protocols_file);
FILE* open_port_file();
void close_port_file(FILE* port_file);
FILE* open_ieee_file();
void close_ieee_file(FILE* ieee_file);

//from comunication_management.c
FRAME* create_element(int frame_number, struct pcap_pkthdr *frame_wrapper, u_char *frame_data);
FRAME* create_linked_list(char* file_name);
void print_linked_list(FRAME *header, FILE *output, IP_ADRESS** ip_adresses, FRAME** arp_duo);

//from printing_info.c
void print_frame_length(FRAME* frame, FILE* output);
int hex_to_dec(const u_char *frame_data, int starting_index);
void print_mac_addresses(const u_char *pcap_pkt_data, FILE* output);
void eth_or_802(FRAME* frame, FILE* output);
void print_data(const u_char *frame_data, int length, FILE* output);
void print_frame_info(FRAME* frame, FILE* output);
void print_ip_sc_dst(FRAME* frame, FILE* output);
FRAME** filtre_protocol(FRAME* header, char* protocol, int* size);
void print_first_full(FRAME** protocol_only, int size, FILE* output);

//from analyze_frame
int is_ipv4(FRAME* frame, IP_ADRESS **adresses);
int is_arp(FRAME* frame);
void print_ipv4_frame(FRAME *frame, FILE *output);
FRAME** print_arp_frames(FRAME *frame, FILE *output, FRAME** arp_duo);
int find_protocol(FRAME* frame, FILE* output);
int find_port(FRAME* frame, FILE* output);

//from ip_adress_management.c
IP_ADRESS* is_presented_in_list(IP_ADRESS *list, IP_ADRESS *requested);
IP_ADRESS* add_element(IP_ADRESS* header, FRAME* frame);
void print_ip_adress(IP_ADRESS* structure, FILE* output);
void print_all_ip_adresses(IP_ADRESS* header, FILE* output);
IP_ADRESS* sent_max_packets(IP_ADRESS* header);
int get_max_packets(IP_ADRESS* header);
IP_ADRESS* create_ip_struct(FRAME* frame, int start);
int are_ip_same(IP_ADRESS* first, IP_ADRESS* second);

//from utils.c
void free_frames_list(FRAME* header);

//from handling_arp.c
int is_syn(FRAME* frame);
int is_fin(FRAME* frame);
int is_reset(FRAME* frame);