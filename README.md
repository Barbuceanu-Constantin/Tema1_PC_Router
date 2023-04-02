322CB Barbuceanu Constantin

    Tema de fata a fost una destul destul de laborioasa necesitand de multe ori crearea antetelor si completarea lor corecta. De asemenea procesul de debuging a fost unuloarecum diferit de cum am fost obisnuit pana acum, insa de multe ori am apelat la modul obisnuit de a folosi printf outputul fiind redirectat in router.out (0 sau 1).

    Abordarea temei a urmarit urmatoarea succesiune de etape: 
    1. Realizarea procesului de forwarding bazat initial pe parsarea tabelei arp statice. Practic in main intr-o bucla infinita se receptioneaza pachete succesiv, iar cazurile de baza verificate intr-un if-else principal sunt cele de IPv4 si ARP, ambele fiind antete peste Ethernet.

    2. Al doilea pas a fost realizarea functiei "icmp" care in functie de al doilea parametru care este un string specific completeaza un pachet de tip icmp si il trimite. Factorul care da specificitate este campul type si campul code in rest procesul este identic indiferent de tipul de mesaj icmp.

    3. Al treilea a fost implementarea functionalitatii de arp.
    Am creat functiile arp_request si arp_reply precum si partea de utilizare a cozii de pachete (functia traverse_waiting_queue de exemplu care parcurge toate elementele din coada si le transmite daca s-a gasit intrare in tabela arp pentru ele, factorul de identificare fiind adresa ip).

    Practic consider ca am implementat:
    *protocolul ARP(30p)
    *procesul de dirijare(30p)
    *protocolul icmp(20p)

    Nu am implementat cautarea eficienta in tabela de rutare.
    Nu am implementat checksum incremental(bonus). 

    PROBLEME INTAMPINATE:
    In decursul temei am intampinat diverse probleme de la completarea gresita a campurilor de icmp sau arp la trimiterea unor parametri gresiti in functiile folosite. De exemplu in momentul cand am inceput sa codez partea de arp mi s-a intamplat ca desi pana atunci testele de forward imi treceau sa nu imi mai treaca acestea odata ce am implementat arpul. Problema si-a gasit solutia in faptul ca atunci cand apelam "get_arp_entry" in main nu trimiteam parametrul (route->next_hop) route fiind intrarea in tabela de rutare returnata de get_best_route.

    ATENTIE!
    --------
    Nu in ultimul rand o problema pe care o semnalez si care are o importanta mare este urmatoarea: eu am terminat (adus tema la stadiul descris mai sus) cam pe 11-12 aprilie (luni-marti) saptamana aceasta. Intre timp am lasat-o "in stand-by" si m-am preocupat de alte sarcini, ca astazi, sambata, dupa ce am aflat ca s-au facut modificari la checker sa incerc local pe noua varianta sa rulez si sa constat cu stupoare ca nu imi mai trec testele. Nu imi dau seama care ar putea fi problema si cum niste modificari teoretic minore pot cauza aceasta. Specific acest fapt in README, dar am pus intrebare si pe forum cu rugamintea si intrebarea daca in acest caz se va lua in considerare si varianta veche a checkerului. Eu sunt convins ca ceea ce am scris este bine in proportie mare raportat la punctele pe care le-am atins din tema, si sunt dispus sa raspund la orice intrebari legate de tema. De asemenea, mentionez ca am inca prima varianta a checkerului si varianta despre care vorbesc a codului sursa din router.c.

