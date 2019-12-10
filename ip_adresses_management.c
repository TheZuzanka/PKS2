// Created by Susanka on 26/11/2019.

#include "header.h"

IP_ADRESS* is_presented_in_list(IP_ADRESS *list, IP_ADRESS *requested){
    IP_ADRESS* actual = list;

    if(list == NULL){
        return 0;
    }

    while(actual != NULL){
        for(int i = 0; i < 4; i++){
            if(actual->address[i] == requested->address[i]){
                if( i == 3 ){
                    return actual;
                }
            }
            else{
                break;
            }
        }
        actual = actual->next;
    }
    return NULL;
}

IP_ADRESS* create_ip_struct(FRAME* frame, int start){
    IP_ADRESS* new_element = (IP_ADRESS*)malloc(sizeof(IP_ADRESS));
    new_element->packet_sent = 1;
    new_element->next = NULL;

    for(int i = 0; i < 4; i++){
        new_element->address[i] = frame->frame_data[start + i];
    }

    return new_element;
}

IP_ADRESS* add_element(IP_ADRESS* header, FRAME* frame){
    IP_ADRESS* new_element = create_ip_struct(frame, 26);
    IP_ADRESS* actual = header;
    IP_ADRESS* me = NULL;

    if(header == NULL){
        return new_element;
    }else{
        if( (me = is_presented_in_list(header, new_element)) == NULL){
            while(actual->next != NULL){
                actual = actual->next;
            }
            actual->next = new_element;
        }
        else{
            (me->packet_sent)++;
        }
        return header;
    }
}

void print_ip_adress(IP_ADRESS* structure, FILE* output){
    for(int i = 0; i< 4; i++){
        fprintf(output, "%d", structure->address[i]);
        if(i < 3){
            fprintf(output, ".");
        }
    }
    fprintf(output, "\n");
}

void print_all_ip_adresses(IP_ADRESS* header, FILE* output){
    IP_ADRESS* actual = header;

    while(actual != NULL){
        print_ip_adress(actual, output);
        actual = actual->next;
    }
}

IP_ADRESS* sent_max_packets(IP_ADRESS* header){
    IP_ADRESS* actual = header;
    IP_ADRESS* winner = NULL;
    int max = 0;

    while(actual != NULL){
        if(actual->packet_sent > max){
            max = actual->packet_sent;
            winner = actual;
        }
        actual = actual->next;
    }

    return winner;
}

int get_max_packets(IP_ADRESS* header){
    IP_ADRESS* actual = header;
    int max = 0;

    while(actual != NULL){
        if(actual->packet_sent > max){
            max = actual->packet_sent;
        }
        actual = actual->next;
    }

    return max;
}

int are_ip_same(IP_ADRESS* first, IP_ADRESS* second){
    for(int i = 0; i < 4; i++){
        if(first->address[i] != second->address[i]){
            return 0;
        }
    }
    return 1;
}