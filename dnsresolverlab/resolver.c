#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

/* Variables used for the DNS Resolver */
int MAX_WIRE_SIZE = 256;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void char2short(unsigned char* charpnt, unsigned short* shortpnt) {
	*shortpnt = (charpnt[0] << 8) | charpnt[1];
}

void char2int(unsigned char* charpnt, int* intpnt) {
	*intpnt = (charpnt[0] << 16) | charpnt[3];
}

void free_answer_entries(dns_answer_entry *ans) {
	dns_answer_entry *next;
	while (ans != NULL) {
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

char* decode_response(char* wire, char* indexp) {
	int first = 0;

	while ((unsigned char)indexp[0] != 0) {
		if ((unsigned char)indexp[0] >= 192) {
			//jump to address contained in next byte
			int offset = indexp[1];
			indexp = wire+offset;
		}
		else if ((unsigned char)indexp[0] <= 47) {
			if ((unsigned char)indexp[0] == 45) {
				//store '-' as byte to a char array
				printf("-");
				indexp += 1;
			}
			else {
				//store '.' as byte to a char array
				if (first > 0) printf(".");
				first = 1;
				indexp += 1;
			}
		}
		else {
			//store current byte to a char array
			printf("%c", (unsigned char)indexp[0]);
			indexp += 1;
		}

	}
}


void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */

	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/*
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
	int offset = 12;
	char *token = strtok(name, ".");
	while (token != NULL) {
		char *temp = token;
		char cnt = strlen(temp);
		memcpy(wire+offset, &cnt, 1);
		offset += 1;
		memcpy(wire+offset, temp, strlen(temp));
		offset += strlen(temp);
		token = strtok(NULL, ".");
	}
	char temp = 0x00;
	memcpy(wire+offset, &temp, 1);
	offset += sizeof(temp);

	return offset;
}

char *name_ascii_from_wire(unsigned char *wire, unsigned char *indexp) {
	/*
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
	char *name = (char*)malloc(MAX_WIRE_SIZE);
	int offset = 0;
	int size = 0;
	char nlchar = 0x00;
	char i;
	memcpy(&i, indexp+offset, 1);

	while (strcmp(&i, &nlchar) != 0) {
		offset++;
		size++;
		memcpy(&i, indexp+offset, 1); //iterate i
	}

	memcpy(name, indexp, size);

	return name;
}

dns_rr rr_from_wire(unsigned char *wire, unsigned char *indexp, int query_only, int wireSize) {
	/*
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */

	/* data in the dns_rr
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
	*/
	dns_rr dnsRR;

	dnsRR.name = name_ascii_from_wire(wire, indexp);
	indexp = indexp + strlen(dnsRR.name);

	char2short(indexp, &dnsRR.type);
	indexp = indexp + sizeof(unsigned short);

	char2short(indexp, &dnsRR.class);
	indexp = indexp + sizeof(unsigned short);

	char2int(indexp, &dnsRR.ttl);
	indexp = indexp + sizeof(int);

	char2short(indexp, &dnsRR.rdata_len);
	indexp = indexp + sizeof(unsigned short);

	char *temp = malloc(MAX_WIRE_SIZE);
	memcpy(temp, indexp, dnsRR.rdata_len);
	dnsRR.rdata = temp;

	return dnsRR;
}


int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/*
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/*
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */

	//Initializes random number generator
	time_t t;
	char newID[2];
	srand((unsigned) time(&t));
	for (int i = 0; i < 2; i++) {
		char temp = (rand() % 255);
		newID[i] = temp;
	}
	char msg[] = {newID[0], newID[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(wire, &msg, 12);

	//makes the question and inserts into wire
	int offset = name_ascii_to_wire(qname, wire);
	for (int i = 0; i < 2; i++) {
		memcpy(wire + offset, &qtype, sizeof(qtype));
		offset = offset + sizeof(qtype);
	}

	return offset;
}

dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire, char *indexp, int wireSize) {
	/*
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */

	dns_rr RR = rr_from_wire(wire, indexp, 1, wireSize);
	unsigned short temp;
	char2short(wire+6, &temp);

	for (int i = 0; i < temp; i++) {
		if (i > 0) RR = rr_from_wire(wire, indexp, 1, wireSize);
		if (RR.type == 1) { // if type 1
			char ipv4[RR.rdata_len];
			sprintf(ipv4, "%i.%i.%i.%i", RR.rdata[0], RR.rdata[1], RR.rdata[2], RR.rdata[3]);
			printf("%s\n", ipv4);
		} else if (RR.type == 5) { // if type 5
			indexp = indexp + strlen(RR.name) + 10 + RR.rdata_len;
			decode_response(wire, indexp);
			printf("\n");
		} else {
			return NULL;
		}
	}
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, char* port) {
	/*
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */

	/* UDP Variables */
	int BUF_SIZE = 500;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s, j;
	char *buf = (char*)malloc(BUF_SIZE);

	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Allow IPv4, IPv6, or both, depending on
				    what was specified on the command line. */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_UDP;          /* Any protocol */

	s = getaddrinfo(server, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket
	   and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
					 rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;                  /* Success */

		close(sfd);
	}

	if (rp == NULL) {               /* No address succeeded */
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);           /* No longer needed */

	if (send(sfd, request, requestlen, hints.ai_flags) < 0) {
		fprintf(stderr, "partial/failed write\n");
		exit(EXIT_FAILURE);
	}

	int receivedBytes = 0;
	if ((receivedBytes = recv(sfd, buf, BUF_SIZE, hints.ai_flags)) < 0) {
		fprintf(stderr, "partial/failed write\n");
		exit(EXIT_FAILURE);
	}

	memcpy(response, buf, BUF_SIZE);

	return receivedBytes;
}

dns_answer_entry *resolve(char *qname, char *server, char *port) {
	unsigned char *wire = (unsigned char*)malloc(MAX_WIRE_SIZE);
	unsigned char *response = (unsigned char*)malloc(MAX_WIRE_SIZE);
	dns_rr_type qtype = 0x0100;

	//canonicalize the name by passing in the name of the query
	canonicalize_name(qname);

	//make the query by calling create_dns_query
	int wireSize = create_dns_query(qname, qtype, wire);

	//send the query to the dns and get a response -- use send_recv_message
	int responseSize = send_recv_message(wire, wireSize, response, server, port);

	//make the ip address using get_answer_address
	unsigned char *indexp = (response + wireSize);
	get_answer_address(qname, qtype, response, indexp, responseSize);

	free(wire);
	free(response);
}

int main(int argc, char *argv[]) {
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
		port = argv[3];
	} else {
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL) {
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL) {
		free_answer_entries(ans_list);
	}
}
