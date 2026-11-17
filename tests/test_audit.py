import ast
import io
import sys
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from astraudit.core import Context, Finding, CHECKS, document, summary
from astraudit import checks
from astraudit.cli import main
from astraudit.reports import html_report, markdown, write_reports


class CoreTests(unittest.TestCase):
    def test_python35_syntax_compatibility(self):
        root = Path(__file__).resolve().parent.parent
        paths = [root / "audit.py"] + list((root / "astraaudit").glob("*.py"))
        for path in paths:
            source = path.read_text(encoding="utf-8")
            if sys.version_info >= (3, 8):
                ast.parse(source, filename=str(path), feature_version=(3, 5))
            else:
                ast.parse(source, filename=str(path))

    def test_unique_registered_ids(self):
        ids=[r[0] for r in CHECKS]
        self.assertEqual(len(ids),47)
        self.assertEqual(len(ids),len(set(ids)))

    def test_counts_ignore_unknown_not_proven(self):
        findings=[Finding('T1','test','test','PASS','ok'),Finding('T2','test','test','SKIP','missing')]
        score=summary(findings)
        self.assertEqual(score['assessed'],1)
        self.assertEqual(score['passed_percent'],100.0)

    def test_nonexistent_binary_does_not_execute(self):
        rc,out=Context(False).command(['/tool/definitely/missing'])
        self.assertIsNone(rc)

    def test_context_does_not_allow_shell_metacharacter_evaluation(self):
        rc,out=Context(False).command(['printf','%s','$(touch /tmp/astraudit-never)'])
        self.assertEqual(rc,0)
        self.assertEqual(out,'$(touch /tmp/astraudit-never)')

    def test_ssh_hardening_status_from_effective_config(self):
        with patch.object(checks,'ssh_values',return_value={'permitrootlogin':'yes','permitemptypasswords':'no'}):
            self.assertEqual(checks.ssh_root(Context(False)).status,'WARN')
            self.assertEqual(checks.ssh_empty(Context(False)).status,'PASS')

    def test_ssh_fails_closed_when_no_config(self):
        with patch.object(checks,'ssh_values',return_value=None):
            self.assertEqual(checks.ssh_root(Context(False)).status,'SKIP')

    def test_shadow_metadata_requires_privileges(self):
        self.assertEqual(checks.shadow(Context(False)).status,'SKIP')

    def test_summary_safe_html(self):
        d=document([Finding('T1','test','<script>alert(1)</script>','WARN','<b>hello</b>')],['test'])
        page=html_report(d)
        self.assertIn('&lt;script&gt;',page)
        self.assertNotIn('<script>alert(1)</script>',page)

    def test_file_output_private(self):
        d=document([Finding('T1','test','safe','PASS','ok')],['test'])
        with tempfile.TemporaryDirectory() as temp:
            paths=write_reports(os.path.join(temp,'reports'),d,['json','md','html'])
            self.assertEqual(len(paths),3)
            for path in paths:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertEqual(json.loads(paths[0].read_text())['summary']['PASS'],1)
            self.assertIn('AstraAudit security assessment',paths[1].read_text())

    def test_cli_list(self):
        output=io.StringIO()
        with redirect_stdout(output):
            status=main(['list'])
        self.assertEqual(status,0)
        self.assertIn('SSH-03',output.getvalue())

    def test_cli_category(self):
        output=io.StringIO()
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(output):
            status=main(['run','--category','kernel','--output',temp,'--format','json'])
            self.assertEqual(status,0)
            paths=list(Path(temp).glob('*.json'))
            self.assertEqual(len(paths),1)
            data=json.loads(paths[0].read_text())
            self.assertTrue(all(v['category']=='kernel' for v in data['findings']))

    def test_report_has_no_raw_password_hash(self):
        d=document([Finding('T1','test','safe','INFO','Count: 1')],['test'])
        self.assertNotIn('root:$6$',json.dumps(d))


if __name__=='__main__':
    unittest.main()