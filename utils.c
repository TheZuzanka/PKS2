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