"""Require exact successful main inputs before building signed release bytes."""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
from validation_inputs import (trusted_run, full_native, complete_jobs, find_native,
                               input_equivalence)


def accepted(run, jobs, sha, workflow):
    if (run.get('head_sha') != sha or run.get('head_branch') != 'main'
            or run.get('event') != 'push' or run.get('conclusion') != 'success'
            or run.get('status') != 'completed'
            or run.get('path') != '.github/workflows/'+workflow):
        return False
    names = [job.get('name') for job in jobs]
    if len(names) != len(set(names)):
        return False
    if workflow == 'ci.yml':
        expected = {f'{platform} / Go {version}' for platform in ('ubuntu-24.04', 'windows-2022', 'macos-15') for version in ('1.26.10','1.27.3')}
        expected |= {'Validation plan','Dependency policy','Accepted validation plan'}
        # The plan job is displayed as its YAML id in the current workflows.
        expected.remove('Validation plan')
        expected.add('plan')
        quality = [n for n in names if n and n.startswith('Race, coverage and CLI smoke')]
        if len(quality) != 1:
            return False
        expected.add(quality[0])
    else:
        expected = {f'Formal policy / {platform} / Go {version}' for platform in ('ubuntu-24.04','windows-2022','macos-15') for version in ('1.26.10','1.27.3')}
        expected.add('Fetch, JSON-RPC and gRPC through MITM')
    succeeded = {j['name'] for j in jobs if j.get('conclusion') == 'success'}
    return expected <= succeeded and all(j.get('conclusion') == 'success' or
        workflow == 'workspace-integration.yml' and j.get('name') == 'development-policy' and j.get('conclusion') == 'skipped' for j in jobs)


def reduced_native(run, jobs, sha, repository):
    quality=[j.get('name') for j in jobs if j.get('name') in ('Race, coverage and CLI smoke test','Race, coverage and CLI smoke tests')]
    if len(quality) != 1:
        return False
    wanted = {'plan': 'success', 'Accepted validation plan': 'success',
              'Dependency policy': 'skipped', quality[0]: 'skipped',
              '${{ matrix.os }} / Go ${{ matrix.go }}': 'skipped'}
    return (trusted_run(run, sha, 'ci.yml', repository) and len(jobs) == len(wanted)
            and {j.get('name'): j.get('conclusion') for j in jobs} == wanted)


def resolve(root, sha, repository, api, native_only=False):
    if repository not in ('FastTLS/fastls-fetch', 'FastTLS/fastls-rpc', 'FastTLS/fastls-mitm'):
        raise ValueError('Untrusted service repository')
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip() != sha:
        raise ValueError('Checked-out consumer differs from requested source')
    proofs=[]
    runs=api('/actions/workflows/ci.yml/runs?head_sha='+sha+'&event=push&status=success&per_page=20')['workflow_runs']
    for run in runs:
        jobs=complete_jobs(api,run)
        if trusted_run(run,sha,'ci.yml',repository) and full_native(run,jobs,repository):
            proofs.append(dict(workflow='ci.yml',run_id=run['id'],head_sha=sha,
                               consumer_sha=sha,mode='exact',jobs=jobs))
            break
        if reduced_native(run,jobs,sha,repository):
            baseline=find_native(root,sha,api,repository)
            if baseline:
                proofs.append(dict(workflow='ci.yml',run_id=run['id'],head_sha=sha,
                                   consumer_sha=sha,mode='verified-source-reuse',native_baseline=baseline,jobs=jobs))
                break
    else:
        raise ValueError('No exact or independently verified native validation for '+sha)
    if repository.endswith('/fastls-rpc') and not native_only:
        runs=api('/actions/workflows/workspace-integration.yml/runs?event=push&status=success&branch=main&per_page=30')['workflow_runs']
        for run in runs:
            source=run.get('head_sha','')
            if not trusted_run(run,source,'workspace-integration.yml',repository):
                continue
            try:
                equivalence=input_equivalence(root,source,sha,'contract')
                jobs=complete_jobs(api,run)
                if accepted(run,jobs,source,'workspace-integration.yml'):
                    proofs.append(dict(workflow='workspace-integration.yml',run_id=run['id'],
                                       head_sha=source,consumer_sha=sha,input_verification=equivalence,jobs=jobs))
                    break
            except (ValueError,KeyError,IndexError,subprocess.CalledProcessError):
                continue
        else:
            raise ValueError('No complete successful contract for unchanged consumer inputs')
    return proofs


def main():
    sha, repository = os.environ['GITHUB_SHA'], os.environ['GITHUB_REPOSITORY']
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise SystemExit('full source SHA required')
    def api(path):
        request = urllib.request.Request('https://api.github.com/repos/'+repository+path,
            headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],
                     'Accept':'application/vnd.github+json','User-Agent':'service-release-gate'})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    proofs=resolve(Path.cwd(),sha,repository,api)
    output=Path(os.environ['ARTIFACT_ROOT'])/'gate.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(proofs,indent=2)+'\n',encoding='utf-8')
    print(json.dumps([{'workflow':p['workflow'],'run_id':p['run_id'],'head_sha':p['head_sha']} for p in proofs]))


if __name__ == '__main__':
    main()
