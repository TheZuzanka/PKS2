// Created by Susanka on 24/11/2019.

#include "header.h"

int is_ipv4_not_add(FRAME* frame){
    int version = (frame->frame_data[14] / 16);
    if(hex_to_dec(frame->frame_data, 13) == 2048){
        if (version == 4){
            return 1;
        }
    }
    else{
        return  0;
    }
}

int is_ipv4(FRAME* frame, IP_ADRESS **adresses){
    int version = (frame->frame_data[14] / 16);
    if(hex_to_dec(frame->frame_data, 13) == 2048){
        if (version == 4){
            int off = (frame->frame_data[14] % 16) * 4;
            off -= 20;
            frame->offset = off / 4;

            //pridam do listu ip adries
            *adresses = add_element(*adresses, frame);
            return 1;
        }
    }
    else{
        return  0;
    }
}

int is_arp(FRAME* frame){
    if(hex_to_dec(frame->frame_data, 13) == 2054){
        return 1;
    }
    return 0;
}

void print_ipv4_frame(FRAME *frame, FILE *output){
    print_frame_info(frame, output);
    fprintf(output, "IPV4\n");

    find_protocol(frame, output);
    print_ports(frame, output);
    print_data(frame->frame_data, frame->frame_wrapper->caplen, output);
}

FRAME** print_arp_frames(FRAME *frame, FILE *output, FRAME** arp_duo){
    print_frame_info(frame, output);
    fprintf(output, "ARP\n");
    print_data(frame->frame_data, frame->frame_wrapper->caplen, output);
    if(frame->frame_data[21] == 0x01){
        //mam request
        if(arp_duo[1] != NULL){
            arp_duo[1] = NULL;
        }
        arp_duo[0] = frame;
    }
    else if(frame->frame_data[21] == 0x02){
        //mam reply
        arp_duo[1] = frame;
        printf("%d frame (requestt) <-> %d frame (reply)", arp_duo[0]->frame_number, arp_duo[1]->frame_number);
        arp_duo[0] = NULL;
        arp_duo[1] = NULL;
    }
    return arp_duo;
}


int find_protocol(FRAME* frame, FILE* output){
    FILE* protocols = open_protocols_file();
    char protocol_name[10];
    int protocol_number;

    while( fscanf(protocols, "%d", &protocol_number) != EOF){
        fscanf(protocols, "%s", protocol_name);

        if(frame->frame_data[23] == protocol_number){
            print_ip_sc_dst(frame, output);
            fprintf(output, "%s\n", protocol_name);
            if(strcmp(protocol_name, "ICMP") == 0){
               //akcia
            }
            else if(strcmp(protocol_name, "TCP") == 0){
                find_port(frame, output);
                //akcia
            }
            else if(strcmp(protocol_name, "UDP") == 0){
                find_port(frame, output);
                //akcia
            }

        }
    }

    close_protocols_file(protocols);
}

int find_port(FRAME* frame, FILE* output){
    FILE* ports = open_port_file();
    char port_name[10];
    int port_number;

    while(fscanf(ports, "%d", &port_number) != EOF){
        fscanf(ports, "%s", port_name);
        int source_port = hex_to_dec(frame->frame_data, 35 + frame->offset);
        int dest_port = hex_to_dec(frame->frame_data, 37 + frame->offset);
        //printf("%d source_port = %d\n", frame->frame_number, source_port);
        //printf("%d dest_port = %d\n", frame->frame_number, dest_port);

        if(source_port == port_number || dest_port == port_number){
            fprintf(output, "%s\n", port_name);
            if(strcmp(port_name, "HTTP") == 0){
                //akcia
            }
            else if(strcmp(port_name, "HTTPS") == 0){
                //akcia
            }
            else if(strcmp(port_name, "TELNET") == 0){
                //akcia
            }
            else if(strcmp(port_name, "SSH") == 0){
                //akcia
            }
            else if(strcmp(port_name, "FTPR") == 0){
                //akcia
            }
            else if(strcmp(port_name, "FTPD") == 0){
                //akcia
            }
            else if(strcmp(port_name, "TFTP") == 0){
                //akcia
            }

        }
    }

    close_port_file(ports);
}