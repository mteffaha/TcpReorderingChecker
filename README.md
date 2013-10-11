TcpReorderingChecker
====================

Project for the course "Internet et réseaux" PolytechNice 2013].

Analyse de reordering dans une trace TCP

Dans ce projet vous devez créer un programme C qui analysera des traces TCP capturées au niveau du récepteur, afin de trouver les paquets TCP qui sont reçu en mauvais ordre, et le “retard” de ces paquets. Vous ferez ensuite une analyse des réseaux à l’aide du programme développé.

Votre programme C :

    Reçoit comme argument le nom du fichier .pcap à analyser.
    Lira un fichier .pcap contenant des paquets capturés avec le logiciel Tcpdump ou Wireshark. Ce fichier .pcap contiendra uniquement des paquets TCP correspondant uniquement à un seul flux.
    Lira paquet par paquet le contenu du fichier .pcap et vérifiera si l’identifiant de ce paquet correspond au paquet attendu. Si ce n’est pas le cas, compter combien de paquets sont vus avant de trouver le paquet manquant (retard du paquet).
    Pour chaque paquet reçu en mauvais ordre, garder dans un fichier texte, en format CSV, l’identifiant du paquet en question et le retard.

Une fois ayant créé votre programme C, vous pouvez procéder à la campagne de test dans laquelle, vous devez télécharger des donnée depuis le serveur de votre choix (en veillant à ce que le temps de téléchargement dépasse au moins la vingtaine de secondes), tandis que le trafique réseau est enregistré par tcpdump (ou wireshark) en format binaire pcap.

Vous procéderez de la façon suivante :

    1er test : Vous lancez un téléchargement long (e.g. Télécharger une image Ubuntu), en utilisant le réseau sans-fil de l’école et à la fin, vous traitez le fichier .pcap avec votre programme C.
    2ème test : Téléchargez autre chose (le but est de télécharger quelque chose d’un serveur différent). À la fin, traitez le fichier .pcap avec votre programme C.
    3ème test : Refaire le test # 1 sur un réseau différent
    4ème test : Refaire le test # 2 sur un réseau différent (le même réseau que vous avez utilisé pour le test # 3).
    5ème, 6ème… test (optionnels) : Exécutez d’autres tests qui vous semblent intéressants, en fonction de ce que vous avez obtenu précédemment. Vous pouvez, par exemple, passer d’un réseau sans-fil à un réseau Ethernet, cibler différents serveurs, etc.

À l’aide des résultats obtenus, vous devez écrire un rapport et commenter les résultats. N’oubliez pas de décrire l’environnement de travail en détail (vous étiez dans le campus, sur un réseau sans-fil, etc). Expliquez par exemple, quel réseau semble être le plus performant en terme de reordering, ou quel serveur.
Ce que vous devez rendre

Le code source de votre programme (qui vous donnera jusqu’à 60% de la note totale, selon la procédure d’évaluation décrite plus tard), un README détaillant tous les aspect nécessaires à connaître pour compiler et exécuter votre programme, plus un Makefile, si nécessaire (10% de la note totale).

Vous devez fournir également le rapport en format PDF (30% de la note totale). Compressez tout (rapport + code source + README + Makefile) dans un fichier compressé en format .tgz. Ne fournisez pas les traces .pcap.
Quelques notes à propos de la manipulation des fichiers .pcap

Avant tout, prenez en compte que l’objectif de cette page est de vous décrire ce que vous devez faire dans le projet. En aucun cas vous trouverez ici une description détaillée et suffisante des technologies et librairies qui vous seront utiles pour la réalisation du projet. C’est donc de votre responsabilité de mieux vous documenter sur elles.

Afin de manipuler de fichiers .pcap, vous allez utiliser la librairie libpcap. Pour compiler votre programme, vous devriez avoir préalablement installé les bibliothèques de développement, disponibles dans les serveurs de dépôt (repositories) Ubuntu. En Ubuntu, les paquets qui fournissent les bibliothèques de développement finissent par “-dev”.

Pour ouvrir un fichier .pcap en mode lecture, libpcap vous fournit la fonction pcap_open_offline(). Et pour parcourir un fichier .pcap existant que nous avons précédemment ouvert avec la fonction pcap_open_offline(), nous faisons appelle à la fonction pcap_next(). pcap_next() va donc nous donner chaque paquet capturé, un par un. Une fois ayant obtenu un paquet, le premier en-tête que vous trouverez correspond à l’en-tête de la trame MAC. Sans aller trop loin dans le détails (nous n’avons absolument pas besoin de le faire), tenez bien en compte le fait que l’en-tête MAC est codé sur les premiers 14 octets du paquet, et que les derniers 2 octets de l’en-tête MAC correspondent à un champ appelé “Type”. Si le type est égal à 0x0800, alors juste après l’en-tête MAC nous avons l’en-tête IP.

Comme toujours, il est très important de fermer les fichiers ouverts. Un fichier ouvert par l’appelle à pcap_open_offline() se ferme par une appelle à la fonction pcap_close().

Prenez également en compte que les librairies à utiliser lors que nous faisons un programme au niveau utilisateur (le “userspace”) se trouvent généralement dans le dossier /usr/include/. Dans ce dossier, le répertoire net/ contient des librairies utiles pour la manipulation des en-têtes MAC, et netinet/ des librairies utiles pour la manipulation des protocoles de la famille INET.
Quelques notes sur la méthode d’évaluation

Nous listerons maintenant les étapes qu’interviendront lors de l’évaluation de votre projet. Notez que ces étapes seront évalue dans cet ordre et que si l’une des étapes n’est pas réussie, les points qui resteront ne seront pas pris en compte.

1. Compilation
2. Exécution réussi du programme
    2.1. Management des erreurs
3. Rapport
4. Qualité du code
5. Point extra : Interface utilisateur ou autre extension

Optionnel (+10%)

Pour chaque paquet retardé de 3 paquets, le protocole TCP considère que le paquet est perdu et il sera renvoyé par l’émetteur. De manière optionnel

    lors que vous détectez un retard de 3 paquets ou plus, vous pouvez indiquer dans un 3ème colonne avec le chiffre 1, que le paquet sera retransmit ou 0, pas de retransmission de l’émetteur.
    trouver le nombre de paquets dupliquées dans une trace.

Quelques liens utiles

    http://www.tcpdump.org/
    http://www.networksorcery.com/enp/default1101.htm
    http://www.tcpipguide.com/



