rule Harmless_Test_Marker : test {
    meta:
        description = "Marqueur de test inoffensif détecté"
        severity = "info"
    strings:
        $marker = "FILE_DETECTOR_TEST_MARKER" ascii wide
    condition:
        $marker
}

rule PowerShell_Download_And_Evaluate {
    meta:
        description = "Motifs PowerShell de téléchargement et d'évaluation"
        severity = "medium"
    strings:
        $shell = "powershell" ascii wide nocase
        $download = "DownloadString" ascii wide nocase
        $evaluate = "Invoke-Expression" ascii wide nocase
    condition:
        all of them
}

rule PowerShell_Encoded_Hidden {
    meta:
        description = "Motifs PowerShell encodé et fenêtre masquée"
        severity = "medium"
    strings:
        $shell = "powershell" ascii wide nocase
        $encoded = "-EncodedCommand" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
    condition:
        all of them
}

