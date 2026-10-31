"""Real Git trees and hostile API receipts exercise the signing boundary."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from validation_inputs import input_equivalence, full_native, find_native, complete_jobs, CURRENT, NEXT
from release_gate import resolve

ROOT=Path(__file__).resolve().parents[1]
REPOSITORY='FastTLS/fastls-rpc'


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.git('init','-q');self.git('config','user.name','Fixture');self.git('config','user.email','fixture@example.invalid')
        self.write('.github/workflows/ci.yml',(ROOT/'.github/workflows/ci.yml').read_text())
        self.write('.github/workflows/development-artifacts.yml','build bytes\n')
        self.write('.github/workflows/workspace-integration.yml','fixed contract and cross-repo pins\n')
        self.write('main.go','package main\n')
        self.write('README.md','Documentation\n')
        self.base=self.commit()
        self.write('scripts/release_gate.py','reviewed signing tools\n')
        self.head=self.commit()
        names=['plan','Dependency policy','Accepted validation plan','Race, coverage and CLI smoke tests']
        names += [f'{p} / Go {v}' for p in ('ubuntu-24.04','windows-2022','macos-15') for v in (CURRENT,NEXT)]
        self.jobs=[dict(name=n,conclusion='success') for n in names]
        self.run=dict(id=1,head_sha=self.base,head_branch='main',event='push',conclusion='success',
                      status='completed',path='.github/workflows/ci.yml',repository=dict(full_name=REPOSITORY))

    def git(self,*args):
        return subprocess.check_output(['git',*args],cwd=self.root,text=True,stderr=subprocess.DEVNULL).strip()

    def write(self,path,text):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8')

    def commit(self):
        self.git('add','.');self.git('commit','-qm','fixture');return self.git('rev-parse','HEAD')

    def api(self,path):
        if path.startswith('/actions/workflows/ci.yml/runs?head_sha='):
            return dict(workflow_runs=[dict(self.run,id=2,head_sha=self.head)])
        if '/workflows/ci.yml/runs?' in path:return dict(workflow_runs=[self.run])
        if '/runs/1/jobs' in path:return dict(total_count=len(self.jobs),jobs=self.jobs)
        if '/runs/2/jobs' in path:
            jobs=[dict(name=n,conclusion='success' if n in ('plan','Accepted validation plan') else 'skipped') for n in
                  ['plan','Accepted validation plan','Dependency policy','Race, coverage and CLI smoke tests','${{ matrix.os }} / Go ${{ matrix.go }}']]
            return dict(total_count=len(jobs),jobs=jobs)
        raise AssertionError(path)

    def test_rederive_direct_native_proof_and_preserve_producer(self):
        proof=find_native(self.root,self.head,self.api,REPOSITORY)
        self.assertEqual(proof['source_sha'],self.base)
        self.assertEqual(proof['consumer_sha'],self.head)
        self.assertEqual(proof['run_id'],1)
        self.assertEqual(resolve(self.root,self.head,REPOSITORY,self.api,native_only=True)[0]['mode'],'verified-source-reuse')

    def test_unknown_production_dependency_generator_and_packaging_inputs_fail(self):
        for path in ('main.go','go.mod','go.sum','inputs.txt','docs/data.json','scripts/build.py','unreviewed.md'):
            self.write(path,'changed');head=self.commit()
            with self.subTest(path=path),self.assertRaises(ValueError):input_equivalence(self.root,self.base,head)

    def test_rename_and_deleted_code_cannot_be_hidden_as_docs(self):
        self.git('mv','main.go','docs.md');head=self.commit()
        with self.assertRaises(ValueError):input_equivalence(self.root,self.base,head)

    def test_generated_markdown_inputs_are_not_docs(self):
        self.write('main.go','package main\n//go:embed README.md\n');base=self.commit()
        self.write('README.md','new bytes');head=self.commit()
        with self.assertRaises(ValueError):input_equivalence(self.root,base,head)

    def test_changed_recipe_toolchain_or_environment_fails(self):
        p=self.root/'.github/workflows/ci.yml';text=p.read_text()
        for before,after in [('go test ','go test -short '),("GOWORK: 'off'","GOWORK: 'auto'"),("go-version: '1.26.10'","go-version: '1.27.3'")]:
            self.write(str(p.relative_to(self.root)),text.replace(before,after));head=self.commit()
            with self.assertRaises(ValueError):input_equivalence(self.root,self.base,head)

    def test_native_only_contract_changes_cannot_reuse_contract(self):
        self.write('.github/workflows/workspace-integration.yml','new cross-repo pins\n');head=self.commit()
        input_equivalence(self.root,self.base,head,'native')
        with self.assertRaises(ValueError):input_equivalence(self.root,self.base,head,'contract')

    def test_build_changes_are_not_publication_tools(self):
        self.write('.github/workflows/development-artifacts.yml','different build\n');head=self.commit()
        with self.assertRaises(ValueError):input_equivalence(self.root,self.base,head)

    def test_unrelated_or_reverse_ancestry_and_bad_revisions_fail(self):
        for source in (self.head,'bad'):
            with self.assertRaises(ValueError):input_equivalence(self.root,source,self.base)

    def test_failed_incomplete_duplicate_untrusted_and_recursive_receipts_fail(self):
        for field,value in [('event','pull_request'),('head_branch','other'),('path','.github/workflows/other.yml'),('conclusion','failure'),('repository',dict(full_name='attacker/repo'))]:
            original=self.run;self.run=dict(original,**{field:value})
            self.assertIsNone(find_native(self.root,self.head,self.api,REPOSITORY));self.run=original
        original=copy.deepcopy(self.jobs)
        for state in ('skipped','failure','cancelled',None):
            self.jobs[-1]['conclusion']=state
            self.assertIsNone(find_native(self.root,self.head,self.api,REPOSITORY))
        self.jobs=original+[original[-1]]
        self.assertFalse(full_native(self.run,self.jobs,REPOSITORY))
        with self.assertRaises(ValueError):complete_jobs(lambda p:dict(total_count=101,jobs=original),self.run)

    def test_consumer_or_repository_substitution_fails(self):
        with self.assertRaises(ValueError):resolve(self.root,self.base,REPOSITORY,self.api)
        with self.assertRaises(ValueError):resolve(self.root,self.head,'attacker/repo',self.api)


if __name__=='__main__':unittest.main()
