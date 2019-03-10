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

### Une SmartCard?

### Le Web plus accéssible aux authentifications par certificats

Aujourd'hui, l'un des principaux défauts de l'authentification par certificats,
c'est qu'elle n'est pas déployée largement : seul un petit nombre de services
l'utilisent.

Cependant, supporté par le constat que les mots de passe perdent
en efficacité, le standard WebAuthn (pour Web Authentication) a récemment été
créé et publiée par le W3C. Ce standard définit une API destinée aux
navigateurs, aux applications web et aux autres plateformes nécessitant une
authentification forte basée sur clés pulbiques.

Les grands du Web ont déjà ont déjà mit en place le support de WebAuthn sur
leurs outils : Windows 10, Android, Google Chrome, Mozilla Firefox,
Microsoft Edge et Safari. L'apparition de ce standard va sans aucun doute
encourager une adoption plus large de ce type d'authentification.

## Attaque sur les smartcard

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
lesquelles la valeur en sortie est la même. Si le MD5 est aujourd'hui obsolèthe,
c'est parce que cet algorithme n'est pas résistant aux collisions.

Si il est possible de produire un message pour lequel la valeur de hashage est
la même que la valeur de hashage d'une clé, il n'est plus necessaire de trouver
la clé et il est possible, par exemple, d'usurper l'identité d'un certificat
en présentant ce message à une autorité de certification.

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

Wikipedia *[Attaque de collisions](https://fr.wikipedia.org/wiki/Attaque_de_collisions)*
