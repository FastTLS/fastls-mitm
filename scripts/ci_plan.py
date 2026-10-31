"""Select development feedback or a frozen candidate without weakening main gates."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import hashlib
import re
import urllib.request

CURRENT = '1.26.10'
NEXT = '1.27.3'


from validation_inputs import (CURRENT, NEXT, TOOLS, CONTRACTS, CI, BUILD,
    documentation, native_recipe, full_native as native_run_valid, find_native, docs_are_inputs)


def native_baseline():
    repo, token = os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GH_TOKEN')
    if repo not in ('FastTLS/fastls-fetch', 'FastTLS/fastls-rpc', 'FastTLS/fastls-mitm') or not token:
        return None
    def api(path):
        request = urllib.request.Request('https://api.github.com/repos/'+repo+path,
            headers={'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.github+json', 'User-Agent': 'native-input-reuse'})
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.load(response)
    try:
        return find_native(Path.cwd(), subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(), api, repo)
    except (OSError, ValueError, KeyError, IndexError, subprocess.CalledProcessError):
        return None


def choose(event, ref, requested, paths):
    if requested not in ('auto', 'quick', 'candidate'):
        raise ValueError('unknown validation mode')
    tag = ref.startswith('refs/tags/')
    docs = paths is not None and bool(paths) and all(documentation(p) for p in paths)
    coordination_files = TOOLS | CONTRACTS | {CI, BUILD}
    coordination = paths is not None and bool(paths) and any(p in coordination_files for p in paths) and all(
        p in coordination_files or documentation(p) for p in paths)
    if coordination:
        root = Path(__file__).resolve().parents[1]
        coordination = all(not p.endswith('.go') or (root/p).is_file() and
                           (root/p).read_text(encoding='utf-8').startswith('//go:build policy_e2e\n') for p in paths)
    if coordination and not tag and requested != 'candidate':
        # These tagged contracts run in Workspace integration. Normal Go
        # package inputs and dependencies are unchanged; preserve its exact
        # earlier native evidence instead of rebuilding the same matrix.
        mode = 'coordination'
    elif docs and not tag and requested != 'candidate':
        mode = 'docs'
    elif tag or ref in ('refs/heads/main', 'refs/heads/v2'):
        mode = 'candidate'
    elif requested == 'candidate' or paths is None or not paths:
        mode = 'candidate'
    elif any(not (p.endswith('.go') or p in ('go.mod', 'go.sum') or p.startswith(('scripts/', '.github/'))) for p in paths):
        mode = 'candidate'
    else:
        mode = 'quick'
    matrix = [] if mode in ('docs', 'coordination') else [dict(os=platform, go=version)
        for platform in (('ubuntu-24.04', 'windows-2022', 'macos-15') if mode == 'candidate'
                         else ('ubuntu-24.04', 'windows-2022'))
        for version in ((CURRENT, NEXT) if mode == 'candidate' else (CURRENT,))]
    return dict(mode=mode, matrix=dict(include=matrix), quality=mode == 'candidate')


def gate(plan, jobs):
    if plan.get('mode') not in ('docs', 'coordination', 'quick', 'candidate') or plan.get('quality') != (plan['mode'] == 'candidate'):
        raise ValueError('invalid validation plan')
    if plan['mode'] == 'coordination':
        proof = plan.get('native_baseline', {})
        if proof.get('verified') is not True or not re.fullmatch('[0-9a-f]{40}', proof.get('sha', '')) or not isinstance(proof.get('run_id'), int):
            raise ValueError('coordination skips require verified native evidence')
    expected = {'plan': True, 'dependency-policy': plan['mode'] in ('quick', 'candidate'),
                'test': plan['mode'] in ('quick', 'candidate'), 'quality': plan['quality']}
    for name, required in expected.items():
        actual = jobs.get(name, {}).get('result')
        if actual != ('success' if required else 'skipped'):
            raise ValueError(f'{name}: expected {"success" if required else "skipped"}, received {actual}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gate', action='store_true')
    args = parser.parse_args()
    if args.gate:
        gate(json.loads(os.environ['VALIDATION_PLAN']), json.loads(os.environ['VALIDATION_JOBS']))
        return
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    base = event.get('pull_request', {}).get('base', {}).get('sha') or event.get('before')
    head = event.get('pull_request', {}).get('head', {}).get('sha') or os.environ.get('GITHUB_SHA')
    if not base or set(base) == {'0'}:
        base = 'HEAD^'
    try:
        paths = subprocess.check_output(['git', 'diff', '--name-only', '--no-renames', base, head or 'HEAD'], text=True).splitlines()
    except subprocess.CalledProcessError:
        paths = None
    plan = choose(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'],
                  event.get('inputs', {}).get('validation', 'auto'), paths)
    if plan['mode'] == 'docs' and docs_are_inputs(Path.cwd(), head or 'HEAD'):
        plan = choose(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'], 'candidate', paths)
    if plan['mode'] == 'coordination':
        proof = native_baseline()
        if proof:
            plan['native_baseline'] = proof
        else:
            plan = choose(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'], 'candidate', paths)
            print('No matching successful native baseline; candidate validation is required')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('plan=' + json.dumps(plan, separators=(',', ':')) + '\n')
        output.write('mode=' + plan['mode'] + '\n')
        output.write('matrix=' + json.dumps(plan['matrix'], separators=(',', ':')) + '\n')
        output.write('quality=' + str(plan['quality']).lower() + '\n')
    print(json.dumps(plan))


if __name__ == '__main__':
    main()
