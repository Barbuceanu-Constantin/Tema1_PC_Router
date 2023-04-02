#include "skel.h"
#include "queue.h"

struct route_table_entry *rtable;
struct arp_entry *arp_table;
char rtable_filename[20];
int rtable_len, arp_table_len;

struct route_table_entry *get_best_route(struct in_addr dest_ip) {
	int idx = -1;	

    for (int i = 0; i < rtable_len; i++) {
        if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {
	    	if (idx == -1) idx = i;
	    	else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
		}
    }
    if (idx == -1) return NULL;
    else return &rtable[idx];
}

struct arp_entry *get_arp_entry(uint32_t next_hop) {
	for (int i = 0; i < arp_table_len; i++) {
        if (memcmp(&next_hop, &arp_table[i].ip, 4) == 0){
			return &arp_table[i];
		}
    }
    return NULL;
}

void icmp(packet *m, char *string) {
	packet icmp;
	memset(&icmp, 0, sizeof(packet));

	struct ether_header *ether_header_icmp = (struct ether_header *) icmp.payload;
	struct ether_header *ether_header = (struct ether_header *)m->payload;
	struct iphdr *ip_hdr_icmp = (struct iphdr *)(icmp.payload + sizeof(struct ether_header));
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	memcpy(ether_header_icmp -> ether_shost, ether_header -> ether_dhost ,6);
	memcpy(ether_header_icmp -> ether_dhost, ether_header -> ether_shost ,6);
	ether_header_icmp -> ether_type = ether_header -> ether_type;

	ip_hdr_icmp->ihl = 5;
	ip_hdr_icmp->version = 4;
	ip_hdr_icmp->tos = 0;
	ip_hdr_icmp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr_icmp->protocol = IPPROTO_ICMP; // = 1;
	ip_hdr_icmp->id = htons(getpid());
	ip_hdr_icmp->frag_off = 0;
	ip_hdr_icmp->ttl = 64;
	ip_hdr_icmp->daddr = ip_hdr->saddr;
	ip_hdr_icmp->saddr = ip_hdr->daddr;
	ip_hdr_icmp->check = 0;
	ip_hdr_icmp->check = ip_checksum((void*)ip_hdr_icmp, sizeof(struct iphdr));

	icmp_hdr->checksum = 0;
	icmp_hdr->code = 0;
	icmp_hdr->un.echo.id = htons(getpid());
	icmp_hdr->un.echo.sequence = htons(64);
	icmp_hdr->checksum = ip_checksum((void*)icmp_hdr, sizeof(struct icmphdr));

	icmp.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	icmp.interface = m->interface;

	if(strcmp(string, "time") == 0) {
		icmp_hdr->type = 11;
	} else if(strcmp(string, "unreachable") == 0) {
		icmp_hdr->type = 3;
	} else if(strcmp(string, "echo_reply") == 0) {
		icmp_hdr->type = 0;
	}

	send_packet(&icmp);
}

void arp_request(uint32_t dest_ip) {
	packet arp;
	struct in_addr dest;
	dest.s_addr = dest_ip;

	struct route_table_entry *best = get_best_route(dest);

	//Ethernet header si ARP header
	struct ether_header *eth_header = (struct ether_header *)arp.payload;
	struct arp_header *arp_header = (struct arp_header *)(arp.payload + sizeof(struct ether_header));

	eth_header->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(best->interface, eth_header->ether_shost);
	hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_header->ether_dhost);

	arp_header->htype = htons(1);		//1 for Ethernet  (format of hardware address)
	arp_header->ptype = htons(0x0800);	//0x0800 for IPv4 (format of protocol address)
	arp_header->hlen = 6;				//Length of hardware adress
	arp_header->plen = 4;				//Length of protocol address
	arp_header->op = htons(1);			//Opcode for ARP Request

	//sha	Sender Hardware Address
	get_interface_mac(best->interface, arp_header->sha);

	//spa	Sender IP Address
	char *string_ip = get_interface_ip(best->interface);
	uint32_t sender_ip = inet_addr(string_ip);
	memcpy(&arp_header->spa, &sender_ip, 4);
	
	//tpa	Target IP Address
	memcpy(&arp_header->tpa, &dest_ip, 4);

	//Target Hardware Adress(tha)
	hwaddr_aton("ff:ff:ff:ff:ff:ff", arp_header->tha);

	arp.interface = best->interface;
	arp.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_packet(&arp);
}

void traverse_waiting_queue(queue q) {
	queue aux = queue_create();
	packet *x;
	int i;

	/*
		Cat timp coada pachetelor mai are elemente in ea, 
		le extrag pe rand, verificand daca ultimul reply ARP primit
		contine adresa MAC destinatie pentru acestea. Verificarea
		se face pe baza IP-ului.
	*/
	while(!queue_empty(q)) {
		x = queue_deq(q);

		struct ether_header *eth = (struct ether_header*)x->payload;
		struct iphdr *ip = (struct iphdr*)(x->payload + sizeof(struct ether_header));

		struct arp_entry *arp_entry = get_arp_entry(ip->daddr);
		if (arp_entry == NULL) {
			queue_enq(aux, x);
		} else {
			memcpy(eth->ether_dhost, arp_entry->mac, 6);
			send_packet(x);
		}
	}

	while(!queue_empty(aux)) {
		x = queue_deq(aux);
		queue_enq(q, x);
	}
}

void arp_reply(packet *m) {
	packet arp;

	struct ether_header *eth_m = (struct ether_header*)m->payload;
	struct ether_header *eth_arp = (struct ether_header*)arp.payload;
	struct arp_header *eth_arp_reply = (struct arp_header*)(arp.payload + sizeof(struct ether_header));
	struct arp_header *eth_arp_m = (struct arp_header*)(m->payload + sizeof(struct ether_header));

	eth_arp->ether_type = eth_m->ether_type;
	memcpy(eth_arp->ether_dhost, eth_m->ether_shost, 6);
	get_interface_mac(m->interface, eth_arp->ether_shost);

	eth_arp_reply->htype = eth_arp_m->htype;
	eth_arp_reply->ptype = eth_arp_m->ptype;
	eth_arp_reply->hlen = 6;
	eth_arp_reply->plen = 4;
	eth_arp_reply->op = htons(2);

	get_interface_mac(m->interface, eth_arp_reply->sha);
	memcpy(eth_arp_reply->tha, eth_arp_m->sha, ETH_ALEN);
	memcpy(&eth_arp_reply->spa, &eth_arp_m->tpa, 4);
	memcpy(&eth_arp_reply->tpa, &eth_arp_m->spa, 4);

	arp.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	arp.interface = m->interface;

	send_packet(&arp);
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	queue q = queue_create();
	char mac[50];

	//Probabil routerul crapă înainte să dea flush la output;
	//setat , i stdout să fie unbuffered.
	setvbuf(stdout, NULL, _IONBF , 0);

	// Do not modify this line
	init(argc - 2, argv + 2);

	//Aloc tabela de rutare
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	//Citesc tabela de rutare
	rtable_len = read_rtable(argv[1], rtable);

	//ALOC TABELA ARP STATIC;
	arp_table = malloc(sizeof(struct arp_entry) * 100000);
	DIE(arp_table == NULL, "memory");
	
	//CITESC TABELA ARP STATICA;
	//arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		//Definesc un pointer la antetul Ethernet.
		struct ether_header *eth = (struct ether_header *) m.payload;

		//Daca avem de a face cu un pachet IP.
		if (ntohs(eth->ether_type) == 0x0800) {
			//Definesc un pointer la antetul IP.
			struct iphdr *iph = ((void *) eth) + sizeof(struct ether_header);

			//Definesc o structura care va contine adresa IP destinatie.
			struct in_addr dest_ip;

			if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0)
				continue;

			//Verific daca pachetul primit este de tip ECHO_REQUEST.
			if(iph->protocol == IPPROTO_ICMP) {
				struct icmphdr* icmp_header = (struct icmphdr*)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				if(icmp_header -> type == 8) {	
					//type = 8 pt. ICMP ECHO_REQUEST
					icmp(&m, "echo_reply");
					continue;
				}
			}

			//Pachetele avand valoarea TTL 1 sau 0 trebuiesc aruncate;
			if (iph->ttl <= 1) {
				icmp(&m, "time");
				continue;
			}
			dest_ip.s_addr = iph->daddr;

			//Obtin cea mai buna ruta catre adresa IP destinatie, interogand tabela de rutare statica.
			struct route_table_entry *route = get_best_route(dest_ip);
			if (route == NULL) {
				icmp(&m, "unreachable");
				continue;
			}

			struct arp_entry *arp = get_arp_entry(route->next_hop);
			if (arp == NULL) {
				//Am inlocuit iph->daddr cu route->next_hop
				arp_request(route->next_hop);
				/*
					Adaug pachetul in coada.
				*/
				packet *aux = (packet *)malloc(sizeof (packet));

				memcpy(aux->payload, m.payload, MAX_LEN);
				aux->interface = m.interface;
				aux->len = m.len;
				queue_enq(q, aux);

				continue;
			}

			iph->ttl--;
			iph->check = 0;
			iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));

			memcpy(eth->ether_dhost, arp->mac, 6);
			get_interface_mac(route->interface, eth->ether_shost);

			//Completez si celelalte doua campuri ale packetului.	
			m.interface = route->interface;
			m.len = sizeof(struct ether_header) + sizeof(struct iphdr);
			send_packet(&m);

		} else if (ntohs(eth->ether_type) == 0x0806) {
			//Daca pachetul primit este de tipul ARP (reply)
			struct arp_header *arph = (struct arp_header *)(m.payload + sizeof(struct ether_header));
			//ARP Reply
			if(arph->op == htons(2)) {
				/*
					Introduc o noua intrare in tabela ARP
					pe baza replyului primit.
				*/
				arp_table[arp_table_len].ip = arph->spa;				//IP
				memcpy(arp_table[arp_table_len].mac, arph->sha ,6);		//MAC
				arp_table_len++;
				
				traverse_waiting_queue(q);
				continue;
			}

			//ARP Request
			if(arph->op == htons(1)) {
				arp_reply(&m);
				continue;
			}
		}
	}
}
