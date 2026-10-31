"""Recompute trusted evidence from immutable Git trees, never from skip claims."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

CURRENT = '1.26.10'
NEXT = '1.27.3'
DOCS = {'README.md', 'DEVELOPMENT.md', 'ADDRESS_POLICY.md', 'AUDIT.md',
        'ARTIFACTS.md', 'INGRESS.md', 'RESPONSE_CONTRACT.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md'}
TOOLS = {'scripts/ci_plan.py', 'scripts/test_ci_plan.py', 'scripts/release_gate.py',
         'scripts/test_release_gate.py', 'scripts/validation_inputs.py',
         'scripts/test_validation_inputs.py', 'scripts/evidence_archive.py',
         'scripts/test_evidence_archive.py', 'scripts/release_download.py',
         'scripts/test_release_download.py', 'scripts/verify_service_releases.py',
         '.github/workflows/service-release-validation.yml',
         '.github/workflows/delivery-validation.yml'}
CONTRACTS = {'.github/workflows/workspace-integration.yml',
             '.github/workflows/address-policy-integration.yml',
             'integration/policy/policy_e2e_test.go',
             'integration/policy/mitm_gateway_e2e_test.go'}
CI = '.github/workflows/ci.yml'
BUILD = '.github/workflows/development-artifacts.yml'


def documentation(path):
    p = PurePosixPath(path)
    return path in DOCS or (path.startswith(('docs/', 'integration/')) and
                           p.suffix == '.md')


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True, encoding='utf-8',
                                   stderr=subprocess.DEVNULL).strip()


def changed(root, base, head):
    # No rename detection: both sides of a rename remain visible to the policy.
    return git(root, 'diff', '--name-only', '--no-renames', base, head).splitlines()


def native_recipe(text):
    selected = []
    for name, end in (('dependency-policy', 'test'), ('test', 'quality'), ('quality', 'accepted')):
        part = text.split('  '+name+':\n', 1)[1].split('  '+end+':\n', 1)[0]
        selected.append('\n'.join(line for line in part.splitlines() if not line.startswith('    if:')))
    selected.append(text.split('\nenv:\n', 1)[1].split('\njobs:', 1)[0])
    # Top-level defaults can change every command even if job text is unchanged.
    selected.append(text.split('\njobs:',1)[0].replace('  actions: read\n',''))
    return hashlib.sha256('\n'.join(selected).encode()).hexdigest()


def docs_are_inputs(root, ref):
    # This repository currently has no embed/generate directives. If introduced,
    # fail conservatively rather than assume Markdown is never a build input.
    result = subprocess.run(['git', 'grep', '-l', '-E', '//go:(embed|generate)', ref,
                             '--', '*.go'], cwd=root, capture_output=True)
    if result.returncode not in (0, 1):
        raise ValueError('Cannot inspect generated inputs')
    return result.returncode == 0


def input_equivalence(root, base, head, scope='native'):
    if scope not in ('native', 'contract'):
        raise ValueError('Unknown input scope')
    if not all(isinstance(s, str) and re.fullmatch('[0-9a-f]{40}', s) for s in (base, head)):
        raise ValueError('Immutable source revisions required')
    if subprocess.run(['git', 'merge-base', '--is-ancestor', base, head], cwd=root,
                      capture_output=True).returncode:
        raise ValueError('Evidence source is not an ancestor')
    paths = changed(root, base, head)
    allowed = TOOLS | {CI, BUILD} | (CONTRACTS if scope == 'native' else set())
    generated = any(documentation(p) for p in paths) and (
        docs_are_inputs(root, base) or docs_are_inputs(root, head))
    for p in paths:
        if documentation(p) and not generated:
            continue
        if p not in allowed:
            raise ValueError('Changed '+scope+' input: '+p)
        # Never allow a replaced/deleted/symlinked test to conceal native input.
        if p in CONTRACTS and p.endswith('.go'):
            before = git(root, 'show', base+':'+p)
            after = git(root, 'show', head+':'+p)
            if not all(t.startswith('//go:build policy_e2e\n') for t in (before, after)):
                raise ValueError('Contract is part of ordinary Go inputs')
    before = git(root, 'show', base+':'+CI)
    after = git(root, 'show', head+':'+CI)
    recipe = native_recipe(after)
    if native_recipe(before) != recipe:
        raise ValueError('Native commands, matrix, environment or toolchain changed')
    if BUILD in paths:
        def build_recipe(ref):
            # Full-history checkout changes provenance verification only.
            text = git(root, 'show', ref+':'+BUILD)
            return '\n'.join(line for line in text.splitlines() if line.strip() != 'fetch-depth: 0')
        if build_recipe(base) != build_recipe(head):
            raise ValueError('Artifact build/signing recipe changed')
    # Tree modes matter too: a control-file symlink must never become executable input.
    for ref in (base, head):
        for line in git(root, 'ls-tree', '-r', ref).splitlines():
            entry, p = line.split('\t', 1)
            if p in paths and entry.split()[0] not in ('100644', '100755'):
                raise ValueError('Nonregular changed input')
    return dict(schema=1, source_sha=base, consumer_sha=head, scope=scope,
                changed_paths=paths, recipe_sha256=recipe, production_inputs_unchanged=True,
                bytes='Evidence covers source tests; archives must retain their actual producer identity.')


def trusted_run(run, sha, workflow, repository=None):
    return (isinstance(sha,str) and re.fullmatch('[0-9a-f]{40}',sha) is not None
            and run.get('head_sha') == sha and run.get('head_branch') == 'main'
            and run.get('event') == 'push' and run.get('conclusion') == 'success'
            and run.get('status') == 'completed'
            and run.get('path') == '.github/workflows/'+workflow
            and (repository is None or run.get('repository', {}).get('full_name') == repository))


def full_native(run, jobs, repository=None):
    names = [j.get('name') for j in jobs]
    required = {f'{p} / Go {v}' for p in ('ubuntu-24.04', 'windows-2022', 'macos-15') for v in (CURRENT, NEXT)}
    quality = [n for n in names if n in ('Race, coverage and CLI smoke test','Race, coverage and CLI smoke tests')]
    if len(quality) != 1:
        return False
    required |= {'plan', 'Dependency policy', 'Accepted validation plan', quality[0]}
    return (trusted_run(run, run.get('head_sha'), 'ci.yml', repository)
            and len(names) == len(set(names)) and set(names) == required
            and all(j.get('conclusion') == 'success' for j in jobs))


def complete_jobs(api, run):
    data = api('/actions/runs/'+str(run['id'])+'/jobs?per_page=100')
    if data.get('total_count') != len(data.get('jobs', [])):
        raise ValueError('Incomplete job evidence')
    return data['jobs']


def find_native(root, head, api, repository):
    runs = api('/actions/workflows/ci.yml/runs?status=success&event=push&branch=main&per_page=30')['workflow_runs']
    for run in runs:
        sha = run.get('head_sha', '')
        if not trusted_run(run, sha, 'ci.yml', repository):
            continue
        try:
            proof = input_equivalence(root, sha, head)
            jobs = complete_jobs(api, run)
            if full_native(run, jobs, repository):
                return dict(proof, run_id=run['id'], sha=sha, verified=True, jobs=jobs)
        except (ValueError, KeyError, IndexError, subprocess.CalledProcessError):
            continue
    return None
