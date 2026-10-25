# Projet : Détecteur de fichiers suspects

## Objectif

Le projet consiste à développer en **Python** un outil capable d’analyser un fichier **sans l’exécuter** afin de détecter différents indicateurs pouvant signaler un fichier suspect ou potentiellement malveillant.

L’objectif n’est pas de considérer une seule anomalie comme une preuve de malware, mais de **combiner plusieurs méthodes de détection** pour produire un rapport explicable.

## 1. Identification du fichier

Le programme récupère les premières informations sur le fichier :

- nom ;
- extension ;
- taille ;
- extensions multiples éventuelles.

L’objectif est notamment de repérer des noms potentiellement trompeurs comme :

`facture.pdf.exe`

Le programme peut alors signaler que l’extension réellement utilisée est `.exe` malgré la présence de `.pdf` dans le nom.

## 2. Vérification par signature binaire

Nous avons étudié les *magic bytes*, c’est-à-dire les premiers octets permettant d’identifier certains formats.

Exemples :

- PDF : `25 50 44 46` (`%PDF`)
- EXE/PE : `4D 5A` (`MZ`)
- ZIP : `50 4B 03 04`
- JPEG : `FF D8 FF`
- PNG : `89 50 4E 47 0D 0A 1A 0A`

Le scanner compare ainsi **l’extension annoncée** avec **le format détecté**.

Par exemple, un fichier nommé `photo.jpg` commençant par `MZ` doit être signalé comme incohérent.

Cette incohérence représente un indicateur de suspicion, mais pas une preuve de malware.

## 3. Calcul du SHA-256

Nous avons ajouté le calcul de l’empreinte **SHA-256** avec la bibliothèque Python `hashlib`.

Cette empreinte permet d’identifier précisément le contenu d’un fichier.

Elle pourra ensuite être comparée à une base contenant des empreintes de fichiers malveillants connus.

À ce stade :

**calcul SHA-256 : réalisé**

**comparaison avec une base de malwares : à réaliser**

## 4. Détection avec YARA

Nous avons intégré **YARA** grâce à `yara-python`.

YARA permet de rechercher des motifs particuliers dans les fichiers grâce à des règles.

Nous avons travaillé sur des règles capables de repérer notamment :

- des marqueurs de test ;
- certaines chaînes PowerShell ;
- plusieurs indices présents simultanément ;
- des chaînes liées à des opérations réseau ;
- des chaînes liées à la création de processus ;
- certaines caractéristiques de fichiers PE.

Important : une correspondance YARA signifie qu’un **motif a été détecté**, pas automatiquement que le fichier est un malware.

## 5. Analyse des exécutables Windows

Nous avons commencé une analyse plus poussée des fichiers **PE (Portable Executable)** tels que :

`.exe`

`.dll`

La bibliothèque utilisée est :

`pefile`

Le programme `pe_analyzer.py` permet notamment de récupérer :

- l’architecture du programme ;
- le nombre de sections ;
- le nom des sections ;
- certaines anomalies structurelles simples.

Exemples de sections rencontrées :

`.text`

`.data`

`.rdata`

`.rsrc`

Le programme peut également signaler certaines structures inhabituelles, par exemple un nombre particulièrement élevé de sections.

Encore une fois, une structure inhabituelle constitue un **indice**, pas une preuve de malware.

## 6. Bibliothèques utilisées

Le projet utilise actuellement principalement :

**Python**

Langage principal du scanner.

**`pathlib`**

Gestion des fichiers et chemins.

**`hashlib`**

Calcul du SHA-256.

**`yara-python`**

Exécution des règles YARA.

**`pefile`**

Analyse de la structure des exécutables Windows PE.

## 7. Architecture actuelle du projet

Une organisation possible est :

```text
file-detector/
│
├── scanner.py
├── pe_analyzer.py
│
├── rules/
│   ├── test_rules.yar
│   └── pe_rules.yar
│
└── samples/
    └── fichiers_de_test
```

`scanner.py` réalise l’analyse générale.

`pe_analyzer.py` réalise l’analyse spécialisée des exécutables Windows.

`rules/` contient les règles YARA.

`samples/` contient les fichiers utilisés pour tester le scanner.

## 8. Ce qui est actuellement réalisé

Le prototype couvre :

- identification du fichier ;
- récupération de l’extension ;
- détection d’extensions potentiellement trompeuses ;
- lecture des signatures binaires ;
- comparaison extension / format apparent ;
- calcul SHA-256 ;
- intégration de YARA ;
- création de règles YARA ;
- analyse de fichiers PE avec `pefile` ;
- extraction des sections PE ;
- premières heuristiques de détection.

## 9. Ce qu’il reste à développer

La prochaine étape prévue est **l’analyse des imports Windows**.

Nous voulons récupérer les fonctions utilisées/importées par un exécutable, puis rechercher des combinaisons intéressantes.

Par exemple :

`VirtualAlloc`

`VirtualProtect`

`WriteProcessMemory`

`CreateRemoteThread`

`CreateProcess`

Certaines de ces fonctions sont parfaitement légitimes lorsqu'elles sont utilisées seules.

Le scanner devra donc éviter une logique du type :

`WriteProcessMemory présent = malware`

et plutôt rechercher des **combinaisons d’indicateurs**.

Après les imports, les prochaines améliorations seront :

1. analyse de l’entropie des sections ;
2. détection d’indices de packing/obfuscation ;
3. amélioration des règles YARA ;
4. comparaison SHA-256 avec une base de réputation ;
5. corrélation des différents indicateurs ;
6. création d’un score de risque explicable ;
7. génération d’un rapport JSON/HTML ;
8. tests sur un jeu contrôlé de fichiers bénins et malveillants ;
9. mesure des faux positifs et faux négatifs.

## État actuel

Le projet est donc actuellement un **prototype d’analyse statique multicritère**.

Il combine déjà :

**Extension + Signature binaire + SHA-256 + YARA + Analyse PE**

La prochaine étape pour reprendre le développement est :

**Analyse des imports PE → analyse des sections → entropie → corrélation des indicateurs → score de risque → rapport final.**