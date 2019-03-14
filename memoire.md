L'authentification par certificats x.509 et smartcard
-----------------------------------------------------

## Introduction

Depuis toujours, l'authentification sur des systèmes informatique est
principalement régie par l'utilisation du couple identifiant / mot de passe.
C'est pourtant un facteur d'identification peu fiables : utilisation du même mot
de passe pour plusieurs - voir tous les - services, mot de passe faible, progrès
technique rendant leur cassage plus efficaces etc. Dans un communiqué de presse
du W3C et de l'Alliance FIDO, "les mots de passe volés, faibles ou par défaut
sont à l'origine de 81% des atteintes à la protection des données".

Il existe des solution pour pallier cette faiblesse, avec notamment
l'introduction d'un ou plusieurs autres facteurs d'authentification (TOTP, SMS
etc.), ou les gestionnaires de mots de passe (keepass, LastPass ...).

L'authentification par certificats semble être une alternative
intéressante au traditionnel mot de passe. Nous allons dans ce mémoire étudier
son fonctionnement, parler de son intégration dans GNU/Linux, parler de sa mise
en œuvre et tenter d'exposer ses limites.

## La norme X.509

La norme X.509 régissant les formats les format pour les certificats à clé
publique. Elle est définie par l'Union Internationale des Télécommunications et
établie :

 - Le **format de certificat**
 - La **liste de révocation** des certificats
 - leurs **attributs**
 - un **algorithme de validation de chemin de certificats**

Contrairement à OpenPGP qui repose sur une toile de confiance, X.509 repose sur
les autorités de certifications : un tiers de confiance délivre les certificats
et fournit les moyens de les vérifier.

Les certificats X.509 sont donc composé de deux éléments : une partie publique
et une partie privée. Ces certificats peuvent assurer plusieurs rôles

### PKI - Infrastructure à clefs publiques

Une infrastructure à clefs publiques est un ensemble d'éléments, qu'ils soient
humain, matériels ou logiciels, destinés à gérer les clefs publiques des
utilisateurs d'un système.

Cette infrastructure est utilisée pour créer, gérer, distribuer et révoquer des
certificats

#### La PKI elle va te crypter l'Internet du digital

Sur Internet, les différentes autorités de certifications assurent les rôles de
PKI : Elle fournissent l'infrastructure pour gérer les certificats permettant
le fonctionnement du chiffrement TLS.

## Une SmartCard?

Maintenant que nous avons parlé de la norme X.509, nous allons parler de notre
**startcard**. D'après Wikipedia ([source](l_sc-wiki)) :

> Une carte à puce est une carte en matière plastique, voire en papier ou en
> carton, de quelques centimètres de côté et moins d'un millimètre d'épaisseur,
> portant au moins un circuit intégré capable de contenir de l'information. Le
> circuit intégré (la puce) peut contenir un microprocesseur capable de traiter
> cette information, ou être limité à des circuits de mémoire non volatile et,
> éventuellement, un composant de sécurité (carte mémoire).

Vous utilisez tous les jours une SmartCard : votre carte SIM, votre carte
bancaire...

Les smartcards qui nous intéressent ici contiennent un espace de stockage, un
microprocesseur et un coprocesseur pour accélérer les opérations
cryptographiques.

![Fonctionnement d'une smartcard](./files/smartcard.svg)

Comme vous pouvez le voir, il n'y a pas de connexion directe entre les contacts
et la mémoire. Pour des raisons évidente de sécurité, tout passe par le système
d'exploitation de la carte. Il en existe une multitude (JavaCard Operating
System, MULTOS, OpenPGP Card, Gnuk etc.)

### Création, stockage et utilisation de certificats

Dans le cas qui nous intéresse, la carte à puce permet de stocker le certificat
et de l'utiliser. Lors de son utilisation, un code PIN sera demandé, le
certificat contenu pourra alors être utilisé pour s'authentifier, signer ou
chiffrer.

Certaines Smartcard permettent la génération de certificats.

### Le Web plus accessible aux authentifications par certificats

Aujourd'hui, l'un des principaux défauts de l'authentification par certificats,
c'est qu'elle n'est pas déployée largement : seul un petit nombre de services
l'utilisent.

Cependant, supporté par le constat que les mots de passe perdent
en efficacité, le standard WebAuthn (pour Web Authentication) a récemment été
créé et publiée par le W3C. Ce standard définit une API destinée aux
navigateurs, aux applications web et aux autres plateformes nécessitant une
authentification forte basée sur clés publiques.

Les grands du Web ont déjà ont déjà mit en place le support de WebAuthn sur
leurs outils : Windows 10, Android, Google Chrome, Mozilla Firefox,
Microsoft Edge et Safari. L'apparition de ce standard va sans aucun doute
encourager une adoption plus large de ce type d'authentification.

## Attaque sur les smartcard

### Attaques par canal auxiliaire

Les attaques par canal auxiliaire regroupe les attaques qui tentent d'exploiter
des failles sur l'implémentation des procédures de sécurité plutôt que sur les
procédures elles-mêmes. Voici une liste de types d'attaques par canal
auxiliaire sur lesquels on va s'attarder car elles touchent les smartcard :

#### Attaque par sondage

Particulièrement invasive, elle consiste à détériorer suffisamment une puce pour
avoir un accès physique aux bus et y lire les bits qui y passent. Il est à noter
que cette attaque est très difficile à mettre en place car elle nécessite du
matériel de pointe (oscilloscope très précis,
chronométrage du passage des bits...), de la rigueur et de la précision sur la
détérioration de la puce, etc.

#### Analyse d'émanations électromagnétiques



#### Analyse de consommation

En fonction des opérations résolues par un processeur, sa consommation en
énergie diffère. En étudiant les variations d'énergie utilisée par un lecteur de
cartes, il est possible de trouver des indices sur la clé privée, sur un
échantillon suffisant. Aujourd'hui, cette attaque peut être aisément
contrecarrée en apposant du bruit sur le circuit ou en le blindant.

#### Attaque par faute



#### Attaque temporelle

Le temps que met un algorithme à s'exécuter donne parfois des indices sur la
constitution d'une clé entrée en paramètre dans cet algorithme, comme le nombre
de bits à 1. A elle seule, cette attaque ne donne pas beaucoup d'informations,
mais elle peut être combinée avec d'autres attaques pour en augmenter son
efficacité.

### Attaques sur les PKI

Même si elle ne touchent pas directement les smartcard, Il est intéressant de
parler des attaque sur les infrastructures à clé publiques.

#### Collision MD5

Le MD5 (pour Message Digest 5) est une fonction de hachage cryptographique
permettant d'obtenir l'empreinte d'un fichier / d'une chaine de caractères.

Une fonction de hachage - pour être robuste - est censé ne donner, pour chaque
valeur en entrée différente, qu'une seule valeur en sortie (valeur de hashage).
On dit d'une fonction de hachage cryptographique qu'elle est *résistante aux
collisions* si il est difficile de trouver deux valeurs en entrée pour
lesquelles la valeur en sortie est la même. Si le MD5 est aujourd'hui obsolète,
c'est parce que cet algorithme n'est pas résistant aux collisions.

S'il est possible de produire un message pour lequel la valeur de hashage est
la même que la valeur de hashage d'une clé privée, il n'est plus nécessaire de
trouver la clé et il est possible, par exemple, d'usurper l'identité d'un
certificat en présentant ce message à une autorité de certification.

Trouver un message produisant le même hash qu'un autre message par force brute
n'exploite pas vraiment cette vulnérabilité. Il existe un scénario qui tire
mieux parti de la collision :
1. L'attaquant créé au préalable deux documents, un "légitime", qu'il demandera
à quelqu'un de signer et un autre qui produit le même hash MD5.
2. L'autre partie, une autorité de certification par exemple, l'accepte et signe
son hash MD5.
3. L'attaquant peut envoyer le deuxième document en y joignant la signature du
premier document, prétendant qu'il a été signé par l'autorité de certification.

Ce scénario a été utilisé, en 2008, par des chercheurs pour créer une fausse
autorité de certification.

## Bibliographie

Stéphane Bortzmeyer *[RFC 5280: Internet X.509 Public Key Infrastructure
Certificate and Certificate Revocation List (CRL)
Profile](https://www.bortzmeyer.org/5280.html)*

Ivan Ristić *[BulletProof SSL and TLS](https://www.feistyduck.com/books/bulletproof-ssl-and-tls)*

Pixis *[Padding oracle](https://beta.hackndo.com/padding-oracle/)*

Romain Bardou, Riccardo Focardi, Yusuke Kawamoto, Lorenzo Simionato, Graham Steel, et al..
*Efficient Padding Oracle Attacks on Cryptographic Hardware.* [Research Report] RR-7944, 2012,
pp.19. <hal-00691958v2>

Marc Zaffagni *[CNETfrance.fr : Vers la fin des mots de passe ? WebAuthn est
désormais un standard du web](https://www.cnetfrance.fr/news/vers-la-fin-des-mots-de-passe-webauthn-est-desormais-un-standard-du-web-39881531.htm)*

W3C *[Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn)*

Wikipedia *[Attaque de collisions](https://fr.wikipedia.org/wiki/Attaque_de_collisions)*,
*[Attaque par canal auxiliaire](https://fr.wikipedia.org/wiki/Attaque_par_canal_auxiliaire)*
