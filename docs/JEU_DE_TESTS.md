# Jeu de fichiers de test inoffensifs

Créé et vérifié le 25 octobre 2026 avec la version 0.2.1 et les règles intégrées.

Ces 12 fichiers synthétiques déclenchent volontairement des alertes. Ils ne contiennent pas de charge malveillante. Les textes sont des listes de mots inertes ; les PE sont des structures artificielles, sans programme fonctionnel, dont le point d’entrée est nul et le drapeau d’image exécutable est retiré. Ils sont destinés à être analysés, pas lancés.

## Utilisation

Dans le logiciel, choisir **Choisir un dossier**, puis sélectionner ce sous-dossier de votre copie du projet :

```text
samples/tests_suspects_inoffensifs
```

Utiliser les règles intégrées (dossier YARA vide dans les réglages). Les préférences personnalisées peuvent changer les résultats. Pour l’archive ZIP, extraire d’abord les fichiers puis choisir le sous-dossier `tests_suspects_inoffensifs` : le scanner ne décompresse pas les ZIP.

## Résultats vérifiés

| Fichier | Score | État | Objectif |
|---|---:|---|---|
| `00_temoin_benin.txt` | 0/100 | `complete` | Témoin bénin : aucun indice attendu. |
| `01_marqueur_test.txt` | 0/100 | `complete` | Marqueur YARA informatif : il doit rester à zéro point. |
| `02_motifs_powershell.txt` | 20/100 | `complete` | Une combinaison de mots détectée par YARA. |
| `03_deux_regles_yara.txt` | 30/100 | `complete` | Deux règles YARA : 40 points bruts, plafonnés à 30. |
| `04_photo.jpg` | 20/100 | `complete` | Extension JPEG, signature PDF : formats incohérents. |
| `05_facture.pdf.exe` | 30/100 | `partial` | Double extension et contenu non PE : identité plafonnée à 30. |
| `06_pe_imports.exe` | 35/100 | `partial` | Combinaison de trois imports PE, sans appel à ces fonctions. |
| `07_pe_sections.exe` | 35/100 | `partial` | Entropie élevée, section inscriptible/exécutable et nom UPX. |
| `08_facture.pdf.exe` | 100/100 | `partial` | Double extension + imports + sections + deux règles YARA : plafond global de 100. |
| `09_pe_tronque.exe` | 0/100 | `partial` | En-tête MZ tronqué : l’analyse ne peut pas conclure. |
| `10_format_inconnu.bin` | 0/100 | `unsupported` | Format non reconnu : le résultat doit rester indéterminé. |
| `11_pe_import_isole.exe` | 0/100 | `partial` | Import isolé : il ne doit pas déclencher la règle de combinaison. |

Les PE synthétiques sont volontairement incomplets et peuvent provoquer des avertissements du parseur. Un état `partial` est donc attendu. Le score et l’état d’analyse sont indépendants : le cas à 100/100 vérifie le calcul du score, pas la dangerosité réelle du fichier.

Ce jeu vérifie le comportement de l’outil ; il ne mesure pas sa capacité à détecter des malwares réels.

Les rapports sont générés localement et ne sont pas fournis dans Git. Depuis la racine du projet, après installation :

```bash
.venv/bin/file-detector samples/tests_suspects_inoffensifs \
  --json reports/tests-inoffensifs.json --html reports/tests-inoffensifs.html --explain
```

Le code de sortie `2` est attendu pour ce lot : certains fichiers provoquent volontairement une analyse incomplète. Choisir d'autres destinations ou ajouter `--force` pour remplacer des rapports existants.
