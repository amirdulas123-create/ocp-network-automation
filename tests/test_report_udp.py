"""Tests de non-regression du rapport CSV pour les scans incluant UDP (v1.5).

Regression corrigee : le detail des vulnerabilites remontees par les scripts NSE
(partie UDP) etait seulement logue dans l'UI et n'apparaissait pas dans le rapport
CSV (_format_nmap_host n'y mettait que l'identifiant compact du script). Le CSV d'un
scan UDP etait donc incomplet par rapport a ce que voyait l'utilisateur.

Ces tests construisent des hotes Nmap realistes (via la vraie classe python-nmap
PortScannerHostDict, un simple dict enrichi) avec une sortie de script snmp-info /
ntp-info contenant des deux-points, pipes, guillemets, virgules et accents, puis
verifient que :
  1. le detail CSV contient la SORTIE des scripts, pas seulement leur id ;
  2. le CSV ecrit par save_report reste bien forme (5 colonnes, texte intact) ;
  3. tous les hotes ayant repondu sont rapportes, meme si l'un d'eux n'a pas de vuln ;
  4. un scan TCP seul reste inchange (aucune section vuln parasite).

Lancer : python -m unittest discover -s tests   (aucune dependance hors stdlib + nmap)
"""

import csv
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main
from nmap import PortScannerHostDict


# Sortie realiste de scripts NSE : deux-points, pipes, guillemets, virgules, parentheses
# et accents -- exactement ce qui casse un CSV mal echappe et ce qui doit survivre ici.
SNMP_INFO_OUTPUT = (
    "  enterprise: net-snmp\n"
    "  engineIDFormat: unknown\n"
    "  snmpEngineBoots: 11\n"
    '  Community: "public" | write access, acces detecte\n'
    "  Cisco IOS Software, C3560 Software (C3560-IPSERVICESK9-M), Version 12.2(55)SE"
)
NTP_INFO_OUTPUT = (
    "  receive time stamp: 2026-07-16T09:12:00\n"
    "  version: ntpd 4.2.8p15@1.3728-o, stratum: 3, precision: -24\n"
    "  system: cisco, processor: unknown"
)


def make_host(tcp=None, udp=None, osmatch=None):
    """Fabrique un PortScannerHostDict minimal mais fidele (meme API que nm[host])."""
    h = PortScannerHostDict()
    h["hostnames"] = []
    h["status"] = {"state": "up"}
    if tcp:
        h["tcp"] = tcp
    if udp:
        h["udp"] = udp
    if osmatch is not None:
        h["osmatch"] = osmatch
    return h


def snmp_vuln_host():
    # Hote qui A repondu : TCP SSH ouvert + SNMP/udp ouvert avec deux scripts NSE
    # qui ont TROUVE quelque chose (communaute public active -> vraie vuln).
    return make_host(
        tcp={22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.2"}},
        udp={161: {"state": "open", "name": "snmp", "product": "", "version": "",
                   "script": {"snmp-info": SNMP_INFO_OUTPUT,
                              "snmp-sysdescr": NTP_INFO_OUTPUT}}},
        osmatch=[{"name": "Cisco IOS 15.0", "accuracy": "96"}],
    )


def plain_tcp_host():
    # Hote sans vuln : juste un service TCP -- doit quand meme etre rapporte.
    return make_host(
        tcp={22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.0"}},
    )


class TestUdpReportDetail(unittest.TestCase):

    def test_vuln_output_present_in_detail(self):
        # Le detail (= champ Detail du CSV) doit contenir la SORTIE des scripts NSE,
        # pas seulement leur identifiant compact.
        detail = main._format_nmap_host(snmp_vuln_host())
        self.assertIn("snmp-info", detail)
        self.assertIn("enterprise: net-snmp", detail)          # sortie snmp-info
        self.assertIn('Community: "public"', detail)           # la vraie trouvaille
        self.assertIn("Version 12.2(55)SE", detail)            # version IOS extraite
        self.assertIn("ntpd 4.2.8p15", detail)                 # sortie du 2e script
        # Et il conserve bien services + OS a cote du bloc vuln.
        self.assertIn("SSH: OpenSSH 8.2", detail)
        self.assertIn("OS: Cisco IOS 15.0", detail)

    def test_detail_is_single_line_after_report_row(self):
        # report_row aplatit les retours a la ligne : indispensable pour qu'Excel n'ait
        # pas une cellule qui deborde sur plusieurs lignes.
        detail = main._format_nmap_host(snmp_vuln_host())
        row = main.report_row("192.168.1.10", "Scan", "Actif", detail)
        self.assertEqual(len(row), 5)
        self.assertNotIn("\n", row[4])
        self.assertNotIn("\r", row[4])

    def test_csv_wellformed_and_complete(self):
        # Scenario cle : plusieurs hotes, dont UN sans vuln. On ecrit un vrai CSV via
        # save_report et on le relit : chaque ligne doit avoir 5 colonnes et le detail
        # des vulnerabilites doit etre present et intact (deux-points/pipes/guillemets
        # correctement echappes par csv.writer).
        rows = [
            main.report_row("192.168.1.10", "Scan", "Actif",
                            main._format_nmap_host(snmp_vuln_host())),
            main.report_row("192.168.1.20", "Scan", "Actif",
                            main._format_nmap_host(plain_tcp_host())),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            old_dir = main.REPORTS_DIR
            main.REPORTS_DIR = tmp
            try:
                path = main.save_report("scan", rows)
            finally:
                main.REPORTS_DIR = old_dir
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8-sig", newline="") as f:
                parsed = list(csv.reader(f))

        # En-tete + 2 hotes, tous a 5 colonnes (pas de decalage du au parsing NSE).
        self.assertEqual(parsed[0], main.REPORT_HEADER)
        self.assertEqual(len(parsed), 3)
        for line in parsed:
            self.assertEqual(len(line), 5, f"colonnes decalees: {line}")

        # L'hote vulnerable garde le detail complet des scripts dans SA ligne.
        vuln_line = next(r for r in parsed[1:] if r[1] == "192.168.1.10")
        self.assertIn("enterprise: net-snmp", vuln_line[4])
        self.assertIn('Community: "public"', vuln_line[4])
        self.assertIn("Version 12.2(55)SE", vuln_line[4])

        # L'hote SANS vuln est bien present lui aussi (aucun hote perdu) et ne porte
        # pas de section vuln parasite.
        plain_line = next(r for r in parsed[1:] if r[1] == "192.168.1.20")
        self.assertIn("SSH: OpenSSH 9.0", plain_line[4])
        self.assertNotIn("Vuln", plain_line[4])

    def test_tcp_only_host_has_no_vuln_section(self):
        # Regression guard : un scan TCP seul (ancien comportement, cf. rapports v1.3-1.4
        # generes avec succes) ne doit PAS gagner de section "Vuln".
        detail = main._format_nmap_host(plain_tcp_host())
        self.assertNotIn("Vuln", detail)
        self.assertIn("SSH: OpenSSH 9.0", detail)


class TestUdpFilteredScripts(unittest.TestCase):

    def test_script_on_open_filtered_port_still_reported(self):
        # En UDP, Nmap conclut souvent "open|filtered" faute de reponse. Un script NSE
        # peut malgre tout avoir produit une sortie : elle ne doit PAS etre perdue.
        host = make_host(
            udp={69: {"state": "open|filtered", "name": "tftp", "product": "", "version": "",
                      "script": {"tftp-enum": "  /startup-config\n  /running-config"}}},
        )
        detail = main._format_nmap_host(host)
        self.assertIn("tftp-enum", detail)
        self.assertIn("startup-config", detail)
        # Le port "open|filtered" n'est pas compte comme un service ouvert...
        self.assertNotIn("TFTP/udp", detail)
        # ... mais la vuln, elle, est bien remontee.
        self.assertIn("Vuln", detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
