# Architecture V2.1

## Chaîne d'analyse

```text
CLI / Tkinter
  → Scanner : paramètres, snapshot YARA, parcours et exclusions
  → isolation : démarrage et surveillance d'un processus par fichier
      → worker : plafonds, snapshots JSON
          → FileAnalyzer : lecture bornée, identité, SHA-256, PE, YARA
  → score recalculé par le parent
  → FileReport / ScanReport
  → interface, JSON, HTML
```

Le processus parent ne charge ni pefile ni yara. Un nouveau processus Python lance le module interne `file_detector.worker` pour chaque fichier ; le fichier analysé n'est jamais exécuté. Les préférences de l'interface sont distinctes des arguments CLI.

## Modules

Les points d'entrée du paquet sont `analyseur` et `file-detector-gui` pour l'interface, et `file-detector` pour la CLI. `scripts/install-launchers.sh` crée leurs raccourcis utilisateur vers l'environnement `.venv` de la copie locale ; aucun chemin personnel n'est intégré dans le code distribué.

- `config.py` : paramètres immuables et validation des limites.
- `settings.py` : lecture/écriture atomique des préférences utilisateur, hors du projet.
- `scanner.py` : orchestration du lot, motifs d'exclusion, progression et annulation.
- `isolation.py` : lancement du worker, surveillance toutes les 50 ms, arrêt/nettoyage, lecture bornée des résultats.
- `worker.py` : limite d'espace virtuel sous Linux, points de sauvegarde et résultat final.
- `analyzer.py` : lecture d'une copie bornée du fichier et orchestration des analyseurs dans l'enfant.
- `identity.py`, `pe.py`, `yara_engine.py` : analyse du contenu. Les sources YARA sont figées avant le lot, leur compilation se fait dans chaque enfant.
- `scoring.py` : déduplication, plafonds et détail des contributions.
- `reports.py` : export JSON et HTML échappé, sans ressources externes.
- `gui.py` : widgets sur le fil principal, supervision dans un fil secondaire, queue d'événements.

## Budgets et arrêt

Par défaut : fichier de 64 Mio maximum, 10 000 fichiers par lot, 15 secondes globales par fichier, 512 Mio par processus, 5 secondes pour le matching YARA. Le délai global comprend démarrage, lecture, compilation et analyse.

La mémoire RSS est surveillée toutes les 50 ms. Linux impose aussi `RLIMIT_AS`, un plafond d'espace virtuel différent de la RAM résidente. Cette protection peut donc refuser une allocation avant que la RSS atteigne le seuil. Ailleurs, la surveillance RSS reste périodique, sans plafond dur dans cette version.

Annulation, dépassement ou interruption clavier : le superviseur tue le worker actif et attend sa terminaison. La réactivité dépend de l'ordonnancement du système ; ce n'est pas une garantie temps réel. La fermeture graphique attend le nettoyage avant de terminer. Un délai ou crash individuel n'arrête pas le reste du lot ; une annulation utilisateur l'arrête.

## Protocole et résultats partiels

Le parent crée un répertoire temporaire privé. Il y écrit la requête JSON contenant chemin, configuration et sources YARA. L'enfant y publie atomiquement des snapshots JSON après identité/SHA-256, après PE et en fin d'analyse. Le parent ne reçoit pas de pickle.

Les résultats sont limités à 4 Mio et le chemin de fichier est rétabli par le parent. Si nécessaire, les détails PE sont omis et le résultat est marqué incomplet. En cas d'interruption, le dernier snapshot terminé conserve les indices déjà obtenus. Les contrôles restants sont marqués `not_completed`. Sans snapshot disponible, le score vaut zéro avec une suspicion indéterminée.

`FileReport.score_breakdown` expose les catégories, points bruts après déduplication, plafonds, contributions, sous-total, réduction globale et total. `ScanReport` utilise le schéma 1.1, référence le jeu de règles par SHA-256 et contient les paramètres effectivement utilisés.

## Exclusions

Un motif est comparé au nom de l'entrée et à son chemin relatif, avec respect de la casse et séparateurs `/`. `*.tmp` exclut les noms correspondants ; `build` exclut un dossier et toute sa descendance. Le compteur dénombre les entrées exclues : un dossier écarté compte pour une entrée, sans énumérer son contenu.

## Ajouter un analyseur

1. Travailler sur le tampon `bytes` dans `FileAnalyzer`, sans exécuter la cible.
2. Produire des `Finding` avec code stable, famille, gravité, explication, preuve et points.
3. Renseigner `checks` et `issues` lorsque la couverture est partielle.
4. Ajouter si nécessaire une famille et son plafond dans `scoring.py`.
5. Tester un cas positif, un contre-exemple bénin et une entrée malformée.
6. Vérifier les scénarios d'interruption et le transport JSON borné.

## Limites

Cette séparation est une isolation de panne et de ressources, pas une sandbox système : le processus enfant garde les droits de l'utilisateur. Les règles personnalisées sont une configuration de confiance ; leur lecture précède la supervision. Les limites de taille/mémoire ne remplacent pas un environnement isolé pour les corpus réellement hostiles.

Un fichier peut changer pendant sa lecture ; les métadonnées observables sont contrôlées, sans garantir un snapshot atomique contre un adversaire. Les liens refusés sont ceux de l'entrée, pas tous les ancêtres du chemin. Les résultats de tout le lot restent en mémoire dans le parent : choisir un nombre maximal de fichiers adapté.

Références : [processus Python](https://docs.python.org/3/library/subprocess.html), [limites de ressources](https://docs.python.org/3/library/resource.html).
