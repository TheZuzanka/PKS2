// Created by Susanka on 19/11/2019.

#include "header.h"

pcap_t *open_pcap_file(char *file_name, char *error_buffer) {
    pcap_t *file;

    if ((file = pcap_open_offline(file_name, error_buffer)) == NULL) {
        printf("Subor %s nenajdeny\n", file_name);
        exit(-1);
    }else{
        printf("Subor %s bol otvoreny.\n", file_name);
    }

    return file;
}

void close_pcap_file(pcap_t *file, char *file_name){
    pcap_close(file);
    printf("Subor %s bol zatvoreny.\n", file_name);
    printf("--------------------------------------------------------------------------\n\n");
}

FILE* open_txt_file(){
    FILE* txt_file;
    if( (txt_file = fopen("output2.txt", "w")) == NULL){
        printf("Vysledny textovy subor sa nepodarilo otvorit.\n");
        printf("--------------------------------------------------------------------------\n\n");
        exit(-1);
    }
    else{
        printf("Subor output2.txt bol otvoreny.\n");
    }

    return txt_file;
}

void close_txt_file(FILE* txt_file){
    if(fclose(txt_file) == EOF){
        printf("Subor output2.txt nebolo mozne zavriet\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
    else{
        printf("Subor output2.txt bol zatvoreny.\n");
        printf("Vysledna analyza ramcov sa nachadza v subore output2.txt.\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
}

FILE* open_protocols_file(){
    FILE* protocols_file;
    if( (protocols_file = fopen("protocols.txt", "r")) == NULL){
        printf("Zdrojovy subor pre protokoly sa nepodarilo otvorit.\n");
        printf("--------------------------------------------------------------------------\n\n");
        exit(-1);
    }
    else{
        printf("Subor protocols.txt bol otvoreny.\n");
    }

    return protocols_file;
}

void close_protocols_file(FILE* protocols_file){
    if(fclose(protocols_file) == EOF){
        printf("Subor protocols.txt nebolo mozne zavriet\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
    else{
        printf("Subor protocols.txt bol zatvoreny.\n");
        printf("Hodnoty pre jednotlive protokoly boli precitane zo suboru protocols.txt\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
}

FILE* open_port_file(){
    FILE* port_file;
    if( (port_file = fopen("ports.txt", "r")) == NULL){
        printf("Zdrojovy subor pre porty sa nepodarilo otvorit.\n");
        printf("--------------------------------------------------------------------------\n\n");
        exit(-1);
    }
    else{
        printf("Subor ports.txt bol otvoreny.\n");
    }

    return port_file;
}

void close_port_file(FILE* port_file){
    if(fclose(port_file) == EOF){
        printf("Subor ports.txt nebolo mozne zavriet\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
    else{
        printf("Subor ports.txt bol zatvoreny.\n");
        printf("Hodnoty pre jednotlive porty boli precitane zo suboru ports.txt\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
}

FILE* open_ieee_file(){
    FILE* ieee_file;
    if( (ieee_file = fopen("ieee.txt", "r")) == NULL){
        printf("Zdrojovy subor pre ieee sa nepodarilo otvorit.\n");
        printf("--------------------------------------------------------------------------\n\n");
        exit(-1);
    }
    else{
        printf("Subor ieee.txt bol otvoreny.\n");
    }

    return ieee_file;
}

void close_ieee_file(FILE* ieee_file){
    if(fclose(ieee_file) == EOF){
        printf("Subor ieee.txt nebolo mozne zavriet\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
    else{
        printf("Subor ieee.txt bol zatvoreny.\n");
        printf("Hodnoty pre moznosti ieee boli precitane zo suboru ieee.txt\n");
        printf("--------------------------------------------------------------------------\n\n");
    }
}