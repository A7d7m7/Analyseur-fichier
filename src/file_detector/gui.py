"""Interface Tk locale. Les opérations de scan s'exécutent hors du fil graphique."""

import queue
import threading
from dataclasses import asdict
from pathlib import Path

from .config import ScanConfig
from .models import ScanReport
from .reports import STATUS_LABELS, write_report
from .scanner import Scanner
from .scoring import score_explanation
from .settings import Preferences, default_settings_path, load_preferences, save_preferences


class Application:
    def __init__(self, root, settings_path: Path | None = None):
        import tkinter as tk
        from tkinter import font, ttk

        self.root = root
        self.settings_path = settings_path or default_settings_path()
        settings_warning = ""
        try:
            self.preferences = load_preferences(self.settings_path)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            self.preferences = Preferences()
            settings_warning = f"Préférences illisibles, valeurs par défaut utilisées : {exc}"
        self.report = None
        self.events = queue.Queue()
        self.stop = threading.Event()
        self.running = False
        self.closing = False
        self.items = []
        self.root.title("Analyseur de fichiers · V2.1")
        # La taille fixe en pixels coupait les widgets lorsque les polices étaient agrandies.
        screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
        width, height = max(1, screen_width - 48), max(1, screen_height - 96)
        self.root.geometry(f"{width}x{height}+24+24")
        self.root.minsize(min(1000, width), min(680, height))
        self.root.configure(background="#f2f5f9")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f2f5f9")
        style.configure("TLabel", background="#f2f5f9", foreground="#182738")
        style.configure("Title.TLabel", font=("TkDefaultFont", 22, "bold"))
        style.configure("TButton", padding=(14, 8))
        self.row_height = max(30, font.nametofont("TkDefaultFont").metrics("linespace") + 12)
        style.configure("Treeview", rowheight=self.row_height)
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="ANALYSE STATIQUE LOCALE", foreground="#ED0808").pack(anchor="w")
        ttk.Label(frame, text="Analyseur de fichiers", style="Title.TLabel").pack(
            anchor="w", pady=(4, 6)
        )
        description = ttk.Label(
            frame, text="Des indices expliqués, sans exécuter les fichiers. Aucun envoi réseau."
        )
        description.pack(anchor="w")
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", pady=18)
        self.file_button = ttk.Button(toolbar, text="Choisir un fichier", command=self.choose_file)
        self.dir_button = ttk.Button(
            toolbar, text="Choisir un dossier", command=self.choose_directory
        )
        self.settings_button = ttk.Button(toolbar, text="Réglages", command=self.open_settings)
        self.cancel_button = ttk.Button(
            toolbar, text="Annuler", command=self.cancel, state="disabled"
        )
        self.export_buttons = []
        for kind in ("html", "json"):
            button = ttk.Button(
                toolbar,
                text=f"Exporter {kind.upper()}",
                command=lambda k=kind: self.export(k),
                state="disabled",
            )
            self.export_buttons.append(button)
        self.action_buttons = [
            self.file_button,
            self.dir_button,
            self.settings_button,
            self.cancel_button,
            *self.export_buttons,
        ]
        self.toolbar_columns = 0

        def arrange_actions(event):
            cell_width = max(button.winfo_reqwidth() for button in self.action_buttons) + 8
            columns = max(1, min(len(self.action_buttons), event.width // cell_width))
            if columns == self.toolbar_columns:
                return
            self.toolbar_columns = columns
            for index in range(len(self.action_buttons)):
                toolbar.columnconfigure(
                    index,
                    weight=1 if index < columns else 0,
                    uniform="actions" if index < columns else "",
                )
            for index, button in enumerate(self.action_buttons):
                button.grid(
                    row=index // columns, column=index % columns, sticky="ew", padx=4, pady=4
                )

        toolbar.bind("<Configure>", arrange_actions)
        self.status = tk.StringVar(value=settings_warning or self.settings_summary())
        status_label = ttk.Label(frame, textvariable=self.status, wraplength=1000)
        status_label.pack(anchor="w")
        self.bar = ttk.Progressbar(frame, mode="indeterminate")
        self.bar.pack(fill="x", pady=(10, 14))
        filters = ttk.Frame(frame)
        filters.pack(fill="x", pady=(0, 8))
        ttk.Label(filters, text="Afficher :").pack(side="left")
        self.filter = tk.StringVar(value="Tous")
        combo = ttk.Combobox(
            filters,
            textvariable=self.filter,
            state="readonly",
            width=26,
            values=["Tous", "Avec indices", "Suspicion ≥ 25", "Analyses non complètes"],
        )
        combo.pack(side="left", padx=8)
        combo.bind("<<ComboboxSelected>>", lambda event: self.refresh())
        self.footer = ttk.Label(
            frame,
            text="Le score est un indice heuristique, pas une probabilité. Aucun indice détecté ne garantit pas l'innocuité.",
            wraplength=940,
        )
        self.footer.pack(side="bottom", anchor="w", pady=(14, 0))

        def wrap_labels(event):
            for label in (description, status_label, self.footer):
                label.configure(wraplength=max(1, event.width - 48))

        frame.bind("<Configure>", wrap_labels)
        panes = ttk.Panedwindow(frame, orient="vertical")
        self.panes = panes
        self.pane_ratio = 0.55
        panes.pack(fill="both", expand=True)
        table_frame = ttk.Frame(panes)
        self.table = ttk.Treeview(
            table_frame,
            columns=("name", "format", "score", "risk", "status"),
            show="headings",
            height=9,
        )
        for column, title, width in [
            ("name", "Fichier", 310),
            ("format", "Format", 80),
            ("score", "Score / 100", 90),
            ("risk", "Suspicion", 170),
            ("status", "Analyse", 180),
        ]:
            self.table.heading(column, text=title)
            self.table.column(column, width=width, minwidth=60)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(fill="both", expand=True)
        self.table.bind("<<TreeviewSelect>>", self.show_details)
        panes.add(table_frame, weight=3)
        from tkinter.scrolledtext import ScrolledText

        self.details = ScrolledText(
            panes,
            wrap="word",
            height=12,
            font=("TkFixedFont", 10),
            background="#ffffff",
            foreground="#182738",
            relief="flat",
            padx=12,
            pady=12,
        )
        panes.add(self.details, weight=2)
        self.set_details(
            "Sélectionnez un résultat pour lire les preuves et les limites de l'analyse."
        )

        def size_panes(event):
            # Garder une place pour le tableau et le détail, même si les polices sont grandes.
            panes.sashpos(0, round(event.height * self.pane_ratio))

        def remember_split(event):
            if panes.winfo_height() > 1:
                self.pane_ratio = max(0.15, min(0.85, panes.sashpos(0) / panes.winfo_height()))

        panes.bind("<Configure>", size_panes)
        panes.bind("<ButtonRelease-1>", remember_split)

        def maximize():
            try:
                root.state("zoomed")
            except tk.TclError:
                try:
                    root.attributes("-zoomed", True)
                except tk.TclError:
                    pass  # La géométrie adaptée à l'écran reste le repli.

        root.after_idle(maximize)
        root.after(100, self.poll)
        root.protocol("WM_DELETE_WINDOW", self.close)

    def settings_summary(self):
        config = self.preferences.scan
        return (
            f"Prêt · {config.max_bytes // (1024 * 1024)} Mio/fichier · {config.max_files} fichiers max · "
            f"{config.analysis_timeout:g} s/fichier · mémoire {config.memory_mb} Mio"
        )

    def apply_settings(self, preferences: Preferences):
        if self.running:
            raise ValueError("Les réglages ne peuvent pas changer pendant une analyse.")
        if preferences.rules_dir and not Path(preferences.rules_dir).is_dir():
            raise ValueError("Le dossier de règles YARA n'existe pas.")
        save_preferences(self.settings_path, preferences)
        self.preferences = preferences
        self.status.set(self.settings_summary())

    def open_settings(self):
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        if self.running:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Réglages de l'analyse")
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=24)
        frame.pack(fill="both", expand=True)
        config = self.preferences.scan
        fields = [
            ("max_size_mb", "Taille maximale par fichier (Mio)", config.max_bytes // (1024 * 1024)),
            ("max_files", "Nombre maximal de fichiers", config.max_files),
            ("analysis_timeout", "Délai global par fichier (secondes)", config.analysis_timeout),
            ("memory_mb", "Budget mémoire par processus (Mio, ≥ 64)", config.memory_mb),
            ("yara_timeout", "Délai du matching YARA (secondes)", config.yara_timeout),
        ]
        variables = {}
        for index, (key, label, value) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=index, column=0, sticky="w", padx=(0, 16), pady=6)
            variables[key] = tk.StringVar(value=str(value))
            ttk.Entry(frame, textvariable=variables[key], width=16).grid(
                row=index, column=1, sticky="ew"
            )
        recursive = tk.BooleanVar(value=config.recursive)
        ttk.Checkbutton(frame, text="Analyser les sous-dossiers", variable=recursive).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=10
        )
        ttk.Label(frame, text="Exclusions (motifs séparés par ;)").grid(
            row=6, column=0, columnspan=2, sticky="w"
        )
        exclusions = tk.StringVar(value="; ".join(config.exclude_patterns))
        ttk.Entry(frame, textvariable=exclusions, width=62).grid(
            row=7, column=0, columnspan=2, sticky="ew", pady=6
        )
        ttk.Label(
            frame,
            text="Exemples : *.tmp ; build ; cache/* — nom ou chemin relatif, casse respectée.",
            wraplength=520,
        ).grid(row=8, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Dossier YARA (vide = règles intégrées)").grid(
            row=9, column=0, columnspan=2, sticky="w", pady=(16, 4)
        )
        rules = tk.StringVar(value=self.preferences.rules_dir)
        ttk.Entry(frame, textvariable=rules).grid(row=10, column=0, sticky="ew")

        def browse():
            selected = filedialog.askdirectory(parent=dialog, title="Dossier de règles YARA")
            if selected:
                rules.set(selected)

        ttk.Button(frame, text="Parcourir", command=browse).grid(row=10, column=1, padx=(10, 0))
        ttk.Label(
            frame,
            text="Réglages conservés sur cette machine. La CLI conserve ses propres options.",
            wraplength=520,
        ).grid(row=11, column=0, columnspan=2, sticky="w", pady=12)

        def apply():
            try:
                new_config = ScanConfig(
                    max_bytes=int(variables["max_size_mb"].get()) * 1024 * 1024,
                    max_files=int(variables["max_files"].get()),
                    recursive=recursive.get(),
                    yara_timeout=int(variables["yara_timeout"].get()),
                    analysis_timeout=float(variables["analysis_timeout"].get()),
                    memory_mb=int(variables["memory_mb"].get()),
                    exclude_patterns=tuple(
                        p.strip() for p in exclusions.get().split(";") if p.strip()
                    ),
                )
                self.apply_settings(Preferences(new_config, rules.get().strip()))
            except (OSError, ValueError) as exc:
                messagebox.showerror("Réglages invalides", str(exc), parent=dialog)
                return
            dialog.destroy()

        ttk.Button(frame, text="Enregistrer", command=apply).grid(row=12, column=1, sticky="e")
        ttk.Button(frame, text="Fermer", command=dialog.destroy).grid(row=12, column=0, sticky="w")

    def cancel(self):
        self.stop.set()
        self.cancel_button.configure(state="disabled")
        self.status.set(
            "Interruption du fichier en cours… Les résultats déjà obtenus seront conservés."
        )

    def choose_file(self):
        from tkinter import filedialog

        path = filedialog.askopenfilename(title="Choisir un fichier à analyser")
        if path:
            self.start(Path(path))

    def choose_directory(self):
        from tkinter import filedialog

        path = filedialog.askdirectory(title="Choisir un dossier à analyser")
        if path:
            self.start(Path(path))

    def start(self, target: Path):
        if self.running:
            return
        self.running = True
        self.stop.clear()
        self.report = None
        self.items = []
        self.refresh()
        self.set_details(f"Cible : {target}\nAnalyse en cours…")
        for button in [
            self.file_button,
            self.dir_button,
            self.settings_button,
            *self.export_buttons,
        ]:
            button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.status.set(f"Analyse de {target}")
        self.bar.start()
        config = self.preferences.scan
        rules_dir = Path(self.preferences.rules_dir) if self.preferences.rules_dir else None

        def work():
            try:
                result = Scanner(config, rules_dir).scan(
                    target,
                    progress=lambda f: self.events.put(("file", f)),
                    cancelled=self.stop.is_set,
                )
                self.events.put(("done", result))
            except Exception as exc:  # noqa: BLE001 -- frontière du fil de travail, erreur affichée
                self.events.put(("error", str(exc)))

        self.worker_thread = threading.Thread(target=work, daemon=False)
        self.worker_thread.start()

    def visible(self, item):
        choice = self.filter.get()
        return (
            choice == "Tous"
            or (choice == "Avec indices" and bool(item.findings))
            or (choice == "Suspicion ≥ 25" and item.score >= 25)
            or (choice == "Analyses non complètes" and item.status != "complete")
        )

    def add_row(self, index, item):
        if self.visible(item):
            self.table.insert(
                "",
                "end",
                iid=str(index),
                values=(item.name, item.format, item.score, item.risk, STATUS_LABELS[item.status]),
            )

    def refresh(self):
        self.table.delete(*self.table.get_children())
        for index, item in enumerate(self.items):
            self.add_row(index, item)

    def poll(self):
        # Traiter par petites séries pour garder la fenêtre réactive pendant un lot.
        for _ in range(100):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "file":
                self.items.append(value)
                self.add_row(len(self.items) - 1, value)
                self.status.set(f"{len(self.items)} fichier(s) examiné(s) · {value.name}")
            else:
                self.running = False
                self.bar.stop()
                self.cancel_button.configure(state="disabled")
                self.file_button.configure(state="normal")
                self.dir_button.configure(state="normal")
                self.settings_button.configure(state="normal")
                if kind == "done":
                    self.report = value
                    summary = value.to_dict()["summary"]
                    state = (
                        "Annulée"
                        if value.cancelled
                        else ("Tronquée" if value.truncated else "Terminée")
                    )
                    self.status.set(
                        f"{state} · {summary['total']} fichier(s) · {summary['with_findings']} avec indices · {summary['incomplete']} analyse(s) non complète(s) · {value.excluded_entries} exclusion(s)"
                    )
                    self.set_details(
                        "\n".join(value.issues)
                        or "Sélectionnez un fichier pour consulter le détail de ses résultats."
                    )
                    for button in self.export_buttons:
                        button.configure(state="normal")
                else:
                    self.status.set("Erreur pendant l'analyse")
                    self.set_details(value)
        if self.closing and not self.running:
            self.root.destroy()
            return
        self.root.after(100, self.poll)

    def set_details(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def show_details(self, event=None):
        selection = self.table.selection()
        if not selection:
            return
        item = self.items[int(selection[0])]
        lines = [
            item.path,
            f"SHA-256 : {item.sha256 or 'Non calculé'}",
            f"Suspicion : {item.risk} · Score : {item.score}/100 · Analyse : {STATUS_LABELS[item.status]}",
            "",
        ]
        lines.extend(f"ATTENTION : {issue}" for issue in item.issues)
        lines.extend(["", "CALCUL DU SCORE", *score_explanation(item)])
        for finding in item.findings:
            lines.extend(
                [
                    "",
                    f"• {finding.title} (+{finding.points} points bruts)",
                    finding.explanation,
                    *[f"  {e}" for e in finding.evidence],
                ]
            )
        if not item.findings:
            lines.append("Aucun indice détecté par les contrôles réalisés.")
        lines.extend(["", "CONTRÔLES", *[f"{k} : {v}" for k, v in item.checks.items()]])
        if item.pe:
            import json

            lines.extend(
                ["", "DÉTAIL PE", json.dumps(asdict(item)["pe"], ensure_ascii=False, indent=2)]
            )
        self.set_details("\n".join(lines))

    def export(self, kind):
        from tkinter import filedialog, messagebox

        if not isinstance(self.report, ScanReport):
            return
        path = filedialog.asksaveasfilename(
            title=f"Exporter le rapport {kind.upper()}",
            defaultextension=f".{kind}",
            initialfile=f"rapport.{kind}",
            filetypes=[(kind.upper(), f"*.{kind}")],
            confirmoverwrite=True,
        )
        if path:
            try:
                write_report(self.report, Path(path), kind, overwrite=True)
                self.status.set(f"Rapport enregistré : {path}")
            except (OSError, ValueError) as exc:
                messagebox.showerror("Export impossible", str(exc))

    def close(self):
        self.stop.set()
        self.closing = True
        if self.running:
            self.root.withdraw()
        else:
            self.root.destroy()


def main():
    try:
        import tkinter as tk
    except ImportError:
        print(
            "Tkinter est absent. Sous Debian/Ubuntu : sudo apt install python3-tk. La CLI reste disponible."
        )
        return 2
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(
            f"Impossible d'ouvrir l'interface graphique : {exc}. Utilisez file-detector en terminal."
        )
        return 2
    Application(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
