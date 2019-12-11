// Created by Susanka on 10/12/2019.

#include "header.h"

int is_syn(FRAME* frame){
    int flag_byte = frame->frame_data[47];

    if((flag_byte & 2) == 2){
        return 1;
    }
    else{
        return 0;
    }
}

int is_fin(FRAME* frame){
    int flag_byte = frame->frame_data[47];

    if((flag_byte & 1) == 1){
        return 1;
    }
    else{
        return 0;
    }
}

int is_reset(FRAME* frame){
    int flag_byte = frame->frame_data[47];

    if((flag_byte & 4) == 4){
        return 1;
    }
    else{
        return 0;
    }
}

int is_syn_ack(FRAME *frame){
    int flag_byte = frame->frame_data[47];

    if((flag_byte & 18) == 18){
        return 1;
    }
    else{
        return 0;
    }
}

int is_tcp(FRAME* frame){
    FILE* protocols = open_protocols_file();
    char protocol_name[10];
    int protocol_number;

    while( fscanf(protocols, "%d", &protocol_number) != EOF){
        fscanf(protocols, "%s", protocol_name);

        if(frame->frame_data[23] == protocol_number){
            if(strcmp(protocol_name, "TCP") == 0){
                return  1;
            }
        }
    }

    close_protocols_file(protocols);
    return 0;
}