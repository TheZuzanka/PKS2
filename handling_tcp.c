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