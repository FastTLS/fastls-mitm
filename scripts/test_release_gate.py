import unittest
from release_gate import accepted


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.sha='a'*40
        self.run=dict(status='completed',head_sha=self.sha,head_branch='main',event='push',conclusion='success',path='.github/workflows/ci.yml')
        names=['plan','Dependency policy','Accepted validation plan','Race, coverage and CLI smoke tests']
        names += [f'{platform} / Go {version}' for platform in ('ubuntu-24.04','windows-2022','macos-15') for version in ('1.26.10','1.27.3')]
        self.jobs=[dict(name=n,conclusion='success') for n in names]

    def test_exact_complete_native_candidate(self):
        self.assertTrue(accepted(self.run,self.jobs,self.sha,'ci.yml'))

    def test_different_source_event_branch_or_recipe_is_rejected(self):
        for field,value in [('head_sha','b'*40),('head_branch','other'),('event','workflow_dispatch'),('conclusion','failure'),('path','.github/workflows/other.yml')]:
            with self.subTest(field=field):
                self.assertFalse(accepted(dict(self.run,**{field:value}),self.jobs,self.sha,'ci.yml'))

    def test_missing_skipped_failed_cancelled_or_duplicate_platform_is_rejected(self):
        self.assertFalse(accepted(self.run,self.jobs[:-1],self.sha,'ci.yml'))
        self.assertFalse(accepted(self.run,self.jobs+[self.jobs[-1]],self.sha,'ci.yml'))
        for state in ['skipped','failure','cancelled',None]:
            jobs=[dict(j) for j in self.jobs]
            jobs[-1]['conclusion']=state
            self.assertFalse(accepted(self.run,jobs,self.sha,'ci.yml'))

    def test_service_contract_requires_all_formal_platforms(self):
        run=dict(self.run,path='.github/workflows/workspace-integration.yml')
        names=[f'Formal policy / {p} / Go {v}' for p in ('ubuntu-24.04','windows-2022','macos-15') for v in ('1.26.10','1.27.3')]
        names+=['Fetch, JSON-RPC and gRPC through MITM']
        jobs=[dict(name=n,conclusion='success') for n in names]+[dict(name='development-policy',conclusion='skipped')]
        self.assertTrue(accepted(run,jobs,self.sha,'workspace-integration.yml'))
        self.assertFalse(accepted(run,jobs[1:],self.sha,'workspace-integration.yml'))
        jobs.append(dict(name='unexpected',conclusion='skipped'))
        self.assertFalse(accepted(run,jobs,self.sha,'workspace-integration.yml'))


if __name__ == '__main__':
    unittest.main()
