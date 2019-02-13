Recherche et définitions
------------------------

## Définitions

### Chiffrement asymétrique

C'est une méthode de chiffrement basée sur une clé privée et une clé publique,
en opposition à la cryptographie symétrique ou chacun des participant partagent
la même clé.

### X.509

L'infrastructure de clé publique X.509 est définie par une norme de l'UIT. Elle
établit entre autres : 

 - Le *format de certificat*
 - La *liste de révocation* des certificats
 - leurs *attributs*
 - un *algorithme de validation de chemin de certificats*

Une autorité de certification attribue des certificats liants une clé publique
à un DN.

### Smartcard

C'est l'autre nom de la carte à puce : Une carte en plastique de moins d'1mm
d'épaisseur et contenant une puce électronique. Cette puce peut contenir des
informations voire un dispositif de sécurité pour les protéger.

Dans le cas des certificats, nous parlerons de smartcard pour désigner le
lecteur, sous forme de clé USB, et la carte intégrée contenant les clé.

### CCID (protocole)

C'est un protocole d'accès à une smartcard par USB. Il permet d'utiliser la
*smartcard* pour l'authentification, le chiffrement de données, la signature.

CE protocole permet l'unification des pilotes de périphériques.

## Documents

### Attaque sur les périphériques PKCS11

Une petite [explication](./files/Padding oracle.epub) du fonctionnement des
attaques par padding oracle avant de commencer. Puis
l'[explication](./files/RR-7944.pdf) d'une faille dans des périphérique CCID.


*[UIT]:Union Internationale des Télécommunication
*[DN]:Distinguish Name
*[CCID]:Chip Card Interface Device
*[USB]:Universal Serial Bus
