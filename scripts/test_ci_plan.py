import copy
import fnmatch
import re
import unittest
from pathlib import Path
from ci_plan import choose, gate, native_run_valid, native_recipe, CURRENT, NEXT


class ValidationPlan(unittest.TestCase):
    def test_development_uses_two_current_platforms(self):
        plan = choose('pull_request', 'refs/pull/1/merge', 'auto', ['tunnel.go'])
        self.assertEqual(plan['mode'], 'quick')
        self.assertEqual(len(plan['matrix']['include']), 2)
        self.assertFalse(plan['quality'])

    def test_main_and_tags_cannot_be_lowered(self):
        for ref in ('refs/heads/main', 'refs/heads/v2', 'refs/tags/v0.1.3'):
            plan = choose('workflow_dispatch', ref, 'quick', ['tunnel.go'])
            self.assertEqual(plan['mode'], 'candidate')
            self.assertEqual(len(plan['matrix']['include']), 6)
            self.assertTrue(plan['quality'])

    def test_docs_skip_go_but_tags_still_validate(self):
        self.assertEqual(choose('push', 'refs/heads/main', 'auto', ['README.md'])['mode'], 'docs')
        self.assertEqual(choose('push', 'refs/tags/v0.1.3', 'auto', ['README.md'])['mode'], 'candidate')
        self.assertEqual(choose('workflow_dispatch', 'refs/heads/dev', 'candidate', ['README.md'])['mode'], 'candidate')

    def test_unknown_missing_or_empty_input_is_conservative(self):
        for paths in (None, [], ['new-tool.bin']):
            self.assertEqual(choose('push', 'refs/heads/dev', 'quick', paths)['mode'], 'candidate')

    def test_gate_rejects_every_unexpected_job_state(self):
        for mode in ('docs', 'coordination', 'quick', 'candidate'):
            plan = dict(mode=mode, quality=mode == 'candidate')
            if mode == 'coordination': plan['native_baseline'] = dict(verified=True, sha='a'*40, run_id=1)
            jobs = {name: dict(result='success' if required else 'skipped') for name, required in {
                'plan': True, 'dependency-policy': mode in ('quick', 'candidate'), 'test': mode in ('quick', 'candidate'), 'quality': mode == 'candidate'}.items()}
            gate(plan, jobs)
            for name in jobs:
                for status in ('failure', 'cancelled', None, 'skipped' if jobs[name]['result'] == 'success' else 'success'):
                    broken = copy.deepcopy(jobs); broken[name]['result'] = status
                    with self.assertRaises(ValueError): gate(plan, broken)
                broken = copy.deepcopy(jobs); del broken[name]
                with self.assertRaises(ValueError): gate(plan, broken)

    def test_invalid_requested_mode_is_rejected(self):
        with self.assertRaises(ValueError): choose('push', 'refs/heads/dev', 'unknown', ['x.go'])

    def test_tagged_coordination_changes_reuse_native_inputs(self):
        paths=['scripts/ci_plan.py', '.github/workflows/ci.yml']
        if (Path(__file__).resolve().parents[1]/'integration/policy/policy_e2e_test.go').exists():
            paths.append('integration/policy/policy_e2e_test.go')
        plan=choose('push', 'refs/heads/main', 'auto', paths)
        self.assertEqual(plan['mode'], 'coordination')
        self.assertFalse(plan['quality'])
        self.assertEqual(choose('push', 'refs/heads/main', 'auto', paths+['go.mod'])['mode'], 'candidate')
        self.assertEqual(choose('push', 'refs/tags/v0.1.3', 'auto', paths)['mode'], 'candidate')
        self.assertEqual(choose('workflow_dispatch', 'refs/heads/main', 'candidate', paths)['mode'], 'candidate')

    def test_documentation_mixed_with_controlled_coordination_preserves_reuse(self):
        paths=['README.md','DEVELOPMENT.md','integration/workspace/README.md',
               '.github/workflows/workspace-integration.yml','scripts/ci_plan.py','scripts/test_ci_plan.py']
        self.assertEqual(choose('push','refs/heads/main','auto',paths)['mode'],'coordination')
        for production in ['go.mod','go.sum','grpc/rpc_server.go','internal/executor.go','scripts/unknown.py']:
            self.assertEqual(choose('push','refs/heads/main','auto',paths+[production])['mode'],'candidate')
        self.assertEqual(choose('push','refs/heads/main','auto',['README.md'])['mode'],'docs')
        self.assertEqual(choose('push','refs/tags/v0.1.2','auto',paths)['mode'],'candidate')

    def test_workspace_paths_ignore_documentation_and_keep_protocol_inputs(self):
        path=Path(__file__).resolve().parents[1]/'.github/workflows/workspace-integration.yml'
        if not path.exists(): self.skipTest('RPC-only workflow')
        text=path.read_text()
        for event,end in [('push','pull_request'),('pull_request','workflow_dispatch')]:
            block=text.split('  '+event+':',1)[1].split('  '+end+':',1)[0]
            patterns=re.findall(r"^      - '([^']+)'",block,re.M)
            def selected(path):
                result=False
                for pattern in patterns:
                    negative=pattern.startswith('!')
                    if fnmatch.fnmatchcase(path,pattern[1:] if negative else pattern): result=not negative
                return result
            self.assertFalse(selected('integration/workspace/README.md'))
            self.assertFalse(selected('integration/policy/notes.md'))
            self.assertFalse(selected('grpc/README.md'))
            for path in ['go.mod','go.sum','grpc/rpc_server.go','internal/servicepolicy/policy.go',
                         'integration/policy/policy_e2e_test.go','.github/workflows/workspace-integration.yml']:
                self.assertTrue(selected(path),path)

    def test_unknown_plan_cannot_authorize_skips(self):
        with self.assertRaises(ValueError): gate(dict(mode='unknown', quality=False), {})
        with self.assertRaises(ValueError): gate(dict(mode='candidate', quality=False), {})
        with self.assertRaises(ValueError): gate(dict(mode='coordination', quality=False), {})

    def test_reuse_requires_all_native_platforms_and_quality(self):
        run=dict(conclusion='success', event='push', head_branch='main', head_sha='c'*40, status='completed', path='.github/workflows/ci.yml')
        jobs=[dict(name=f'{os} / Go {go}', conclusion='success') for os in ('ubuntu-24.04','windows-2022','macos-15') for go in (CURRENT,NEXT)]
        jobs += [dict(name=name,conclusion='success') for name in ('plan','Dependency policy','Accepted validation plan','Race, coverage and CLI smoke tests')]
        self.assertTrue(native_run_valid(run,jobs))
        for i in range(len(jobs)):
            self.assertFalse(native_run_valid(run,jobs[:i]+jobs[i+1:]))
            for status in ('failure','cancelled','skipped',None):
                broken=copy.deepcopy(jobs);broken[i]['conclusion']=status
                self.assertFalse(native_run_valid(run,broken))
        self.assertFalse(native_run_valid(dict(run,conclusion='failure'),jobs))

    def test_native_recipe_rejects_changed_execution_inputs(self):
        workflow=(Path(__file__).resolve().parents[1]/'.github/workflows/ci.yml').read_text()
        expected=native_recipe(workflow)
        for old,new in [('go test ', 'go test -short '),
                        ("GOWORK: 'off'", "GOWORK: 'auto'"),
                        ('fail-fast: false','fail-fast: true'),
                        ("go-version: '1.26.10'", "go-version: '1.27.3'")]:
            self.assertIn(old,workflow)
            self.assertNotEqual(native_recipe(workflow.replace(old,new)),expected)
        selected=workflow.replace("    if: needs.plan.outputs.mode == 'quick' || needs.plan.outputs.mode == 'candidate'", "    if: needs.plan.outputs.mode != 'docs'")
        self.assertEqual(native_recipe(selected),expected)


if __name__ == '__main__': unittest.main()
