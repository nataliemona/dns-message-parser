/*  References Used
    http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
    http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm
    https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    https://notes.shichao.io/tcpv1/ch11/
    https://www.rfc-editor.org/rfc/rfc1035.txt
*/

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
#define QUESTION_FIXED_DATA_LEN 4
#define ANSWER_FIXED_DATA_LEN 10
#define MAX_DNS_MSG_LEN 512
#define MAX_LABEL_SIZE 63
#define COMPRESSION_LABEL 0xC0

#define IPv4_MAX_LEN 15
#define IPv6_MAX_LEN 39

// Header Flags
#define HDR_QR 0x8000
#define HDR_OPCODE 0x7800
#define HDR_AA 0x0400
#define HDR_TC 0x0200
#define HDR_RD 0x1000
#define HDR_RA 0x0080
#define HDR_RCODE 0x000F

// RR Types
#define A 1
#define CNAME 5
#define AAAA 28


const char* opcode_names[] = {"QUERY", "IQUERY", "STATUS", NULL, "NOTIFY", "UPDATE"};

const char* rcode_names[] = {
    "NOERROR", "FORMATERROR", "SERVERFAILURE",
    "NAMEERROR", "NOTIMPLEMENTED", "REFUSED",
    "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"};

struct header {
    uint16_t identifier;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
};

struct question_fixed_data {
    uint16_t type_val;
    uint16_t class_val;
};

struct answer_fixed_data {
    uint16_t type_val;
    uint16_t class_val;
    unsigned ttl;
    uint16_t rd_length;
};

int print_label_n(unsigned char* msg, off_t offset, int n);

int print_label(unsigned char* msg, off_t offset) {
    return print_label_n(msg, offset, MAX_LABEL_SIZE);
}

/*
    Interpret DNS label format and print label.
*/
int print_label_n(unsigned char* msg, off_t offset, int n) {
    int idx = 0;
    unsigned num = msg[offset];

    while (true) {
        if (num >= COMPRESSION_LABEL) {
            // Extract offset from compression label
            off_t label_offset = ((msg[offset + idx] & 0x3F) << 8) + msg[offset + idx + 1];
            print_label(msg, label_offset);
            return idx + 2;
        } 
        
        if (num > 0) {
            idx += 1;
            num -= 1;
            printf("%c", msg[offset + idx]);
            if (idx >= n) {
                return idx + 1;
            }
        } else {
            idx += 1;
            if (idx >= n) {
                return idx + 1;
            }
            num = msg[offset + idx];
            printf(".");
            if (num == 0) {
                return idx + 1;
            }
        }
    }
}

/*
    Convert from Resource Record Type value to name
*/
void rr_type(uint16_t type_val, char* buf) {
    switch (type_val) {
        case A:
            strcpy(buf, "A");
            break;
        case CNAME:
            strcpy(buf, "CNAME");
            break;
        case AAAA:
            strcpy(buf, "AAAA");
            break;
        default: {
            fprintf(stderr, "ERROR: Resource Record Type value %i unsupported\n", type_val);
            exit(1);
        }
    }       
}


/*
    Print DNS Message Header

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
void print_header(struct header* h) {

    uint16_t flags = htons(h->flags);

    printf(";; ->>HEADER<<- ");

    uint16_t opcode = flags & HDR_OPCODE;
    printf("opcode: %s, ", opcode_names[opcode]);

    uint16_t rcode = flags & HDR_RCODE;
    printf("status: %s, ", rcode_names[rcode]);

    printf("id: %u\n", htons(h->identifier));

    printf(";; flags:");
    if (flags & HDR_QR) {
        printf(" qr");
    }
    if (flags & HDR_AA) {
        printf(" aa");
    }
    if (flags & HDR_TC) {
        printf(" tc");
    }
    if (flags & HDR_RD) {
        printf(" rd");
    }
    if (flags & HDR_RA) {
        printf(" ra");
    }
    printf(
        "; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
        htons(h->qd_count),
        htons(h->an_count),
        htons(h->ns_count),
        htons(h->ar_count)
    );
}


/*
    Print one entry in the DNS message question section starting at
    offset in the DNS message (msg)

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
off_t print_question(unsigned char* msg, off_t offset) {
    unsigned char* ptr = msg + offset;

    printf(";");
    int label_len = print_label(msg, offset);

    struct question_fixed_data rr;
    memcpy((void*)&rr, ptr + label_len, 4);

    unsigned short query_class = htons(rr.class_val);
    if (query_class == 1) {
        printf("\t\tIN");
    } else if (query_class == 255) {
        printf("\t\tALL CLASSES");
    } else {
        printf("\t\tNO CLASS");
    }
    char rr_type_name[10];
    rr_type(htons(rr.type_val), rr_type_name);
    printf("\t%s\n", rr_type_name);

    return offset + label_len + QUESTION_FIXED_DATA_LEN;
}


/*
    Print one entry in the DNS message answer section starting at
    offset in the DNS message (msg)
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
off_t print_answer(unsigned char* msg, off_t offset) {
    unsigned char* ptr = msg + offset;

    // NAME
    int n_bytes_read = print_label(msg, offset);

    struct answer_fixed_data data;
    memcpy((void*)&data, ptr + n_bytes_read, sizeof(struct answer_fixed_data));

    unsigned short rr_type_val = htons(data.type_val);
    //unsigned short rr_class = htons(data.class);
    int ttl = htonl(data.ttl);

    char rr_type_name[10];
    rr_type(rr_type_val, rr_type_name);
    printf("\t\t%u\t%s\t%s\t", ttl, "IN", rr_type_name);

    n_bytes_read += ANSWER_FIXED_DATA_LEN;

    // RDLENGTH and RDATA
    int rd_len = htons(data.rd_length);
    switch (rr_type_val) {
        case A: {
            char buf[IPv4_MAX_LEN + 1];
            struct in_addr addr;
            memcpy(&addr.s_addr, ptr + n_bytes_read, rd_len);
            printf("%s\n", inet_ntop(AF_INET, &addr, buf, IPv4_MAX_LEN + 1));
            break;
        }
        case CNAME: {
            print_label_n(msg, offset + n_bytes_read, rd_len);
            printf("\n");
            break;
        }
        case AAAA: {
            char buf[IPv6_MAX_LEN + 1];
            struct in6_addr addr;
            memcpy(&addr.s6_addr, ptr + n_bytes_read, rd_len);
            printf("%s\n", inet_ntop(AF_INET6, &addr, buf, IPv6_MAX_LEN + 1));
            break;
        }
    }

    return offset + 2 + ANSWER_FIXED_DATA_LEN + rd_len;
}


/*
    Print the DNS Message
*/
void print_msg(unsigned char* msg) {
    struct header h;
    memcpy((void*)&h, msg, HEADER_BYTES);

    print_header(&h);

    printf("\n;; QUESTION SECTION:\n");
    int n_questions = htons(h.qd_count);
    off_t offset = HEADER_BYTES;
    for (int i = 0; i < n_questions; i++) {
        offset = print_question(msg, offset);
    }

    printf("\n;; ANSWER SECTION:\n");
    int n_answers = htons(h.an_count);
    for (int i = 0; i < n_answers; i++) {
        offset = print_answer(msg, offset);
    }
}

int main() {
    int blen = (MAX_DNS_MSG_LEN * 2) + 1;
    unsigned char buf[blen];
    memset((void*)buf, 0, blen);

    int local = 1;

    if (local) {

        // Test Case 0
        //const char* input = "a01d81800001000100000000076578616d706c6503636f6d0000010001c00c0001000100001bbc00045db8d822";

        // Test Case 1
        //const char* input = "9b4c84000001000200000000037777770a636c6f7564666c61726503636f6d0000010001c00c000100010000012c000468107c60c00c000100010000012c000468107b60";

        // Test Case 2
        const char* input = "7ebd84000001000200000000037777770a636c6f7564666c61726503636f6d00001c0001c00c001c00010000012c001026064700000000000000000068107c60c00c001c00010000012c001026064700000000000000000068107b60";

        // Test Case 3
        //const char* input = "762081800001000200000000037777770773706f7469667903636f6d0000010001c00c0005000100000102001f12656467652d7765622d73706c69742d67656f096475616c2d67736c62c010c02d000100010000006c000423bae019";
        
        memcpy(buf, input, strlen(input));
        //printf("input: %s\n", buf);
    } else {
        scanf("%s", buf);
    }

    // Convert input string to bytes
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

    print_msg(msg);

    free(msg);
    return 0;
}
