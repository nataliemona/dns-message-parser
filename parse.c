// References
// http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
// http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
// https://notes.shichao.io/tcpv1/ch11/

#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HEADER_BYTES 12

const char* opcode_names[] = {"QUERY", "IQUERY", "STATUS", NULL, "NOTIFY", "UPDATE"};

const char* rcode_names[] = {
    "NOERROR", "FORMATERROR", "SERVERFAILURE",
    "NAMEERROR", "NOTIMPLEMENTED", "REFUSED",
    "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"};

// Maybe move to C++ and make this a map?
const char* rr_types[] = {NULL, "A", "NS", "MD", "MF", "CNAME"};

struct header {
    uint16_t identifier;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct question_footer {
    uint16_t type;
    uint16_t class;
};

struct answer_data {
    uint16_t type;
    uint16_t class;
    unsigned ttl;
};

void print_header(struct header* h) {
    uint16_t id = htons(h->identifier);
    uint16_t flags = htons(h->flags);

    bool qr = flags & 0x8000;
    uint16_t opcode = flags & 0x7800;
    bool aa = flags & 0x0400;
    bool tc = flags & 0x0200;
    bool rd = flags & 0x0100;
    bool ra = flags & 0x0080;
    uint16_t rcode = flags & 0x000F;

    printf(";; ->>HEADER<<- ");
    printf("opcode: %s, ", opcode_names[opcode]);
    printf("status: %s, ", rcode_names[rcode]);
    printf("id: %u\n", id);

    printf(";; flags:");
    if (qr) {
        printf(" qr");
    }
    if (aa) {
        printf(" aa");
    }
    if (tc) {
        printf(" tc");
    }
    if (rd) {
        printf(" rd");
    }
    if (ra) {
        printf(" ra");
    }
    printf(
        "; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
        htons(h->qdcount),
        htons(h->ancount),
        htons(h->nscount),
        htons(h->arcount));
}

int print_label(unsigned char* label) {
    int idx = 0;
    int num = (int)label[0];

    while (num != 0) {
        while (num > 0) {
            idx += 1;
            num -= 1;
            printf("%c", label[idx]);
        }
        idx += 1;
        num = label[idx];
        printf(".");
    }

    return idx + 1;
}

off_t print_question(unsigned char* msg, off_t offset) {
    unsigned char* ptr = msg + offset;

    printf(";");
    int label_len = print_label(ptr);

    struct question_footer f;
    memcpy((void*)&f, ptr + label_len, 4);

    unsigned short query_class = htons(f.class);
    if (query_class == 1) {
        printf("\t\tIN");
    } else if (query_class == 255) {
        printf("\t\tALL CLASSES");
    } else {
        printf("\t\tNO CLASS");
    }
    switch (htons(f.type)) {
        case 1:
            printf("\tA");
            break;
        case 28:
            printf("\tAAAA");
            break;
    }
    //printf("\t%s", rr_types[htons(f.type)]);

    printf("\n");

    return offset + label_len + sizeof(struct question_footer);
}

off_t print_answer(unsigned char* msg, off_t offset) {
    unsigned char* ptr = msg + offset;

    // // Debug
    // printf("offset, %lld\n", offset);
    // for (int i = offset; i < offset + 16; i++) {
    //     printf("%02x ", msg[i]);
    // }
    // printf("\n");

    // Read compressed label
    if (ptr[0] >= 0xc0) {
        off_t label_offset = ((ptr[0] & 0x3F) << 8) + ptr[1];
        print_label(msg + label_offset);
        ptr += 2;
    } else {
        int label_len = print_label(ptr);
        ptr += label_len;
    }

    struct answer_data data;
    memcpy((void*)&data, ptr, sizeof(struct answer_data));

    unsigned short rr_val = htons(data.type);
    //unsigned short rr_class = htons(data.class);
    int ttl = htonl(data.ttl);

    printf("\t\t%u\t%s\t", ttl, "IN");

    switch (rr_val) {
        case 1:
            printf("A\t");
            break;
        case 28:
            printf("AAAA\t");
            break;
    }

    ptr += sizeof(struct answer_data);
    int rd_len;
    memcpy((void*)&rd_len, ptr, 2);
    rd_len = htons(rd_len);

    ptr += 2;

    if (rr_val == 28) {
        char buf[50];
        struct in6_addr addr;
        memcpy(&addr.s6_addr, ptr, rd_len);
        const char* addr_str = inet_ntop(AF_INET6, &addr, buf, 50);
        printf("%s\n", addr_str);
    }

    if (rr_val == 1) {
        for (int i = 0; i < rd_len; i++) {
            if (i != 0) {
                printf(".");
            }
            printf("%i", ptr[i]);
        }
        printf("\n");
    }

    return offset + sizeof(struct answer_data) + 2 + rd_len + 2;
}

int main() {
    unsigned char buf[400];
    /* Enter your code here. Read input from STDIN. Print output to STDOUT */
    memset((void*)buf, 0, 400);

    int local = 1;

    if (local) {

        // Test Case 0
        //const char* input = "a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822";

        // Test Case 1
        //const char* input = "9b4c84000001000200000000037777770a636c6f7564666c61726503636f6d0000010001c00c000100010000012c000468107c60c00c000100010000012c000468107b60";

        // Test Case 2
        const char* input = "7ebd84000001000200000000037777770a636c6f7564666c61726503636f6d00001c0001c00c001c00010000012c001026064700000000000000000068107c60c00c001c00010000012c001026064700000000000000000068107b60";

        memcpy(buf, input, strlen(input));
        //printf("input: %s\n", buf);
    } else {
        scanf("%s", buf);
    }

    // Convert input to bytes
    int msg_len = (strlen((const char*)buf) / 2) + 1;
    unsigned char* msg = (unsigned char*)malloc(msg_len);
    memset((void*)msg, 0, msg_len);
    for (int i = 0; i < msg_len; i++) {
        unsigned char hex_byte[2];
        hex_byte[0] = buf[(i * 2)];
        hex_byte[1] = buf[(i * 2) + 1];
        unsigned char byte;
        int r = sscanf((const char*)hex_byte, "%02hhx", &byte);
        if (r < 0) {
            break;
        }

        memcpy((void*)(msg + i), &byte, 1);
    }

    // // Debug
    // for (int i = 0; i < 68; i++) {
    //     printf("%02x ", msg[i]);
    // }
    // printf("\n");

    struct header h;
    memcpy((void*)&h, msg, HEADER_BYTES);

    print_header(&h);
    printf("\n");
    printf(";; QUESTION SECTION:\n");
    int n_questions = htons(h.qdcount);
    int n_answers = htons(h.ancount);
    off_t offset = HEADER_BYTES;
    for (int i = 0; i < n_questions; i++) {
        offset = print_question(msg, offset);
    }
    printf("\n");
    //printf("offset=%ld\n", offset);
    printf(";; ANSWER SECTION:\n");
    for (int i = 0; i < n_answers; i++) {
        offset = print_answer(msg, offset);
    }
    //printf("offset! %ld\n", offset);
    free(msg);
    return 0;
}
