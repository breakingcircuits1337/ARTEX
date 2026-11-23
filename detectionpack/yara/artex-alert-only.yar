/*
 * ARTEX Defense: curated detection-only YARA signatures.
 * Adapted from artex-defender-github-ready.zip/detection/yara/artex.yar.
 * Original MIT attribution: Breaking Circuits, 2026.
 *
 * Matching a legitimate ARTEX installation is not evidence of malware.
 * Run ONLY on explicitly authorized offline/endpoint files. Exclude this
 * rule pack, the ARTEX repository, test fixtures and your own binaries from
 * scan roots to avoid misleading self-matches.
 */
rule ARTEX_Binary_Strings {
    meta:
        description = "Heuristic for ELF artifacts containing ARTEX-related strings"
        severity = "MEDIUM"
        impact = "alert-only"
    strings:
        $ua1 = "artex-enrich/1.0" ascii wide
        $ua2 = "artex-probe" ascii wide
        $pkg1 = "github.com/Autumn-27/norma" ascii wide
        $pkg2 = "github.com/Autumn-27/ARTEX" ascii wide
        $db = "exploration_graph" ascii wide
        $worker = "agent.Worker" ascii wide
    condition:
        filesize < 100MB and uint32(0) == 0x464C457F
        and 2 of ($ua*, $pkg*, $db, $worker)
}

rule ARTEX_JSP_Webshell_Numbered {
    meta:
        description = "Heuristic for a small JSP executing an external command"
        severity = "HIGH"
        impact = "alert-only"
    strings:
        $exec1 = "Runtime.getRuntime().exec(" ascii wide
        $exec2 = "ProcessBuilder(" ascii wide
        $request = "request.getParameter(" ascii wide
        $shell1 = "/bin/sh" ascii wide
        $shell2 = "cmd.exe" ascii wide
    condition:
        filesize < 50KB and $request
        and 1 of ($exec*)
        and 1 of ($shell*)
}

rule ARTEX_Probe_File {
    meta:
        description = "Heuristic for small files containing artex-probe markers"
        severity = "LOW"
        impact = "alert-only"
    strings:
        $probe1 = "artex-probe" ascii wide nocase
        $probe2 = "artex_probe" ascii wide nocase
    condition:
        filesize < 1MB and any of them
}
