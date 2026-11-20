"""`python -m vuln_triage` で CLI を実行する（pip が作る vuln-triage.exe を使わずに済む）。"""
from .cli import main

main(prog_name="vuln-triage")
