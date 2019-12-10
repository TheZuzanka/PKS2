// Created by Susanka on 08/12/2019.

#include "header.h"

void free_frames_list(FRAME* header){
    FRAME* actual = header->next;
    FRAME* freeing = NULL;

    while(actual != NULL){
        freeing = actual;
        actual = actual->next;

        free(freeing);
    }

    free(header);
}

int are_same_comunication(IP_ADRESS* ip1s, IP_ADRESS* ip1d, IP_ADRESS* ip2s, IP_ADRESS* ip2d, int port1s, int port1d, int port2s, int port2d){
    if(are_ip_same(ip2d, ip1s) && are_ip_same(ip1d, ip2s) && port2d == port1s && port2s == port1d){
        return 1;
    }
    else{
        return 0;
    }
}