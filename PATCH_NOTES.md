# Notes de version


## 0.2.1 —   22 octobre 2026

### Correctif d'affichage

- Ouverture agrandie selon l'écran, avec demande de maximisation au gestionnaire de fenêtres.
- Boutons répartis sur plusieurs lignes si nécessaire ; libellés adaptés à la largeur disponible.
- Hauteur des lignes ajustée à la police et partage initial explicite entre résultats et détails pour éviter un tableau masqué sur écran à forte mise à l'échelle.

### Fiabilité

- Chaque fichier est analysé dans un processus jetable : les bibliothèques natives PE/YARA ne sont plus chargées par le superviseur.
- Délai global par fichier de 15 secondes par défaut, incluant démarrage, lecture, compilation YARA et parseurs.
- Budget mémoire de 512 Mio par processus ; surveillance RSS à intervalle de 50 ms. Linux ajoute un plafond dur d'espace virtuel `RLIMIT_AS`.
- Annulation du fichier en cours et arrêt du lot, avec conservation des résultats déjà obtenus. Fermeture de la fenêtre et Ctrl+C nettoient le processus actif.
- Un arrêt brutal, un délai dépassé ou une allocation refusée ne sont jamais présentés comme une analyse rassurante. Le lot continue après un échec individuel.
- Échanges par JSON borné à 4 Mio, snapshots atomiques et aucune désérialisation pickle.
- Snapshot des sources YARA au début du lot : règles stables, limitées à 128 fichiers / 8 Mio. Compilation isolée pour chaque fichier.

### Interface et rapports

- Dialogue Réglages : taille maximale, nombre de fichiers, récursion, délais global/YARA, mémoire, exclusions et dossier de règles.
- Préférences locales persistantes hors du projet, dans le dossier de configuration de l'utilisateur.
- Exclusions par motif de nom ou chemin relatif, comptage des entrées exclues.
- Décomposition du score : points bruts après déduplication, plafonds par famille, contributions, sous-total, plafond global et total.
- JSON au schéma 1.1 ; HTML et interface affichent le calcul. Nouveaux états `timeout`, `resource_limit`, `cancelled`.
- CLI : `--timeout`, `--memory-mb`, `--exclude` et `--explain`.

### Validation

- 50 tests réussis sous Linux avec écran virtuel : anciens tests et nouveaux scénarios d'isolation, mémoire, annulation, arrêt brutal, préférences, exclusions, score et interface.
- Contrôle Ruff réussi.
- La mesure de faux positifs/faux négatifs sur un corpus représentatif reste à réaliser.

### Limites

- L'isolation des processus et les budgets ne constituent pas une sandbox de sécurité : pas de restriction des appels système, des accès disque ou réseau au niveau du système d'exploitation.
- Sur les systèmes autres que Linux, la mémoire est surveillée périodiquement via RSS ; ce n'est pas un plafond dur. Les tests de cette livraison ont été exécutés sous Linux.
- Le démarrage d'un processus et la recompilation des règles par fichier ajoutent un coût aux scans de nombreux petits fichiers.

## 0.2.0 — 21 Septembre 2026

Première implémentation disponible dans ce dossier. Le périmètre du prototype est repris depuis le document de conception fourni ; aucun ancien code n'était présent à migrer.

### Ajouts

- Paquet Python installable avec commandes `file-detector` et `file-detector-gui`.
- Identification, signature binaire, extensions trompeuses et SHA-256.
- Intégration YARA et règles pédagogiques avec marqueur de test sans score.
- Analyse PE : architecture, imports normaux/différés, sections, entropie et permissions.
- Combinaisons d'imports et indices de packing, avec explications et preuves.
- Score plafonné par famille, niveau de suspicion et état d'analyse séparés.
- Scan de dossiers, progression, limites, exclusions et gestion des erreurs.
- Rapports JSON versionnés et HTML autonomes avec échappement des données analysées.
- Interface Tkinter locale, scan en arrière-plan, filtres, détails, annulation et exports.
- README, documentation d'architecture et exemples inoffensifs.
- Tests automatisés du moteur, des rapports, de la CLI et de l'interface.

### Limites connues

- Analyse approfondie réservée aux PE ; documents et archives ne sont pas interprétés.
- Pas de base de réputation, historique SQLite, quarantaine ou analyse dynamique.
- Heuristiques pédagogiques à calibrer ; performances de détection non mesurées sur corpus réel.
- Pas d'isolation des parseurs ; seul le matching YARA dispose d'un délai explicite.

### Validation effectuée

- Python 3.14.8, pefile 2024.8.26, yara-python 4.5.4 sous Linux.
- 27 tests réussis avec affichage virtuel, dont scan, sélection, filtre et export de l'interface.
- Contrôle Ruff et vérification des dépendances réussis.
- Rapports de démonstration générés pour les trois échantillons inoffensifs.
- Interface inspectée visuellement ; note sur le score visible en bas de fenêtre.
- Paquet wheel construit dans `dist/`.
- Ces validations ne mesurent pas un taux de détection sur des malwares réels.

## Prototype décrit — avant 0.2.0

Document initial : identification, magic bytes, SHA-256, YARA et premières sections PE. Cette entrée décrit la conception fournie, sans attester d'une version de code récupérée.

