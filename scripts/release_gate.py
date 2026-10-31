"""Require exact successful main inputs before building signed release bytes."""
import json
import os
from pathlib import Path
import re
import urllib.request


def accepted(run, jobs, sha, workflow):
    if (run.get('head_sha') != sha or run.get('head_branch') != 'main'
            or run.get('event') != 'push' or run.get('conclusion') != 'success'
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
    proofs=[]
    workflows=['ci.yml']
    if repository.endswith('/fastls-rpc'):
        workflows.append('workspace-integration.yml')
    for workflow in workflows:
        runs=api('/actions/workflows/'+workflow+'/runs?head_sha='+sha+'&event=push&status=success&per_page=20')['workflow_runs']
        for run in runs:
            job_result=api('/actions/runs/'+str(run['id'])+'/jobs?per_page=100')
            jobs=job_result['jobs']
            if job_result['total_count'] == len(jobs) and accepted(run,jobs,sha,workflow):
                proofs.append({'workflow':workflow,'run_id':run['id'],'head_sha':sha,'jobs':jobs})
                break
        else:
            raise SystemExit('No complete successful main validation for '+workflow+' at '+sha)
    output=Path(os.environ['ARTIFACT_ROOT'])/'gate.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(proofs,indent=2)+'\n',encoding='utf-8')
    print(json.dumps([{'workflow':p['workflow'],'run_id':p['run_id'],'head_sha':p['head_sha']} for p in proofs]))


if __name__ == '__main__':
    main()
