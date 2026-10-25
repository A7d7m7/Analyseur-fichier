#!/usr/bin/env bash
# Installer les raccourcis utilisateur sans modifier les fichiers du shell.
set -euo pipefail

usage() {
    printf '%s\n' 'Usage : bash scripts/install-launchers.sh [--bin-dir DOSSIER]'
    printf '%s\n' 'Crée analyseur, file-detector-gui et file-detector dans ~/.local/bin par défaut.'
}

bin_dir="${HOME}/.local/bin"
if [[ "${1:-}" == '--help' ]]; then
    usage
    exit 0
elif [[ $# -eq 2 && "$1" == '--bin-dir' ]]; then
    bin_dir="$2"
elif [[ $# -ne 0 ]]; then
    usage >&2
    exit 2
fi

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
gui="${project_dir}/.venv/bin/file-detector-gui"
cli="${project_dir}/.venv/bin/file-detector"
if [[ ! -x "$gui" || ! -x "$cli" ]]; then
    printf '%s\n' "Installez d'abord le projet dans .venv (voir README.md)." >&2
    exit 1
fi

mkdir -p -- "$bin_dir"
bin_dir="$(cd -- "$bin_dir" && pwd -P)"
names=(analyseur file-detector-gui file-detector)
targets=("$gui" "$gui" "$cli")

# Vérifier tous les conflits avant de créer le premier lien.
for index in "${!names[@]}"; do
    destination="${bin_dir}/${names[index]}"
    if [[ -e "$destination" || -L "$destination" ]]; then
        if [[ ! -L "$destination" ]] || [[ "$(readlink -- "$destination")" != "${targets[index]}" ]]; then
            printf 'Conflit : %s existe déjà ; aucun fichier existant ne sera remplacé.\n' "$destination" >&2
            exit 1
        fi
    fi
done

for index in "${!names[@]}"; do
    destination="${bin_dir}/${names[index]}"
    if [[ ! -L "$destination" ]]; then
        ln -s -- "${targets[index]}" "$destination"
    fi
    printf 'Disponible : %s\n' "$destination"
done

case ":${PATH}:" in
    *":${bin_dir}:"*) printf '%s\n' 'Vous pouvez lancer analyseur depuis n’importe quel dossier.' ;;
    *) printf 'Ajoutez %s à votre PATH pour utiliser ces commandes (voir README.md).\n' "$bin_dir" ;;
esac
