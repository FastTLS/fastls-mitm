"""Select development feedback or a frozen candidate without weakening main gates."""
import argparse
import json
import os
from pathlib import Path
import subprocess

CURRENT = '1.26.10'
NEXT = '1.27.3'


def choose(event, ref, requested, paths):
    if requested not in ('auto', 'quick', 'candidate'):
        raise ValueError('unknown validation mode')
    tag = ref.startswith('refs/tags/')
    docs = paths is not None and bool(paths) and all(
        p.endswith(('.md', '.rst', '.txt')) or p in ('LICENSE', 'NOTICE') for p in paths)
    if docs and not tag and requested != 'candidate':
        mode = 'docs'
    elif tag or ref in ('refs/heads/main', 'refs/heads/v2'):
        mode = 'candidate'
    elif requested == 'candidate' or paths is None or not paths:
        mode = 'candidate'
    elif any(not (p.endswith('.go') or p in ('go.mod', 'go.sum') or p.startswith(('scripts/', '.github/'))) for p in paths):
        mode = 'candidate'
    else:
        mode = 'quick'
    matrix = [] if mode == 'docs' else [dict(os=platform, go=version)
        for platform in (('ubuntu-24.04', 'windows-2022', 'macos-15') if mode == 'candidate'
                         else ('ubuntu-24.04', 'windows-2022'))
        for version in ((CURRENT, NEXT) if mode == 'candidate' else (CURRENT,))]
    return dict(mode=mode, matrix=dict(include=matrix), quality=mode == 'candidate')


def gate(plan, jobs):
    expected = {'plan': True, 'dependency-policy': plan['mode'] != 'docs',
                'test': plan['mode'] != 'docs', 'quality': plan['quality']}
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
        paths = subprocess.check_output(['git', 'diff', '--name-only', base, head or 'HEAD'], text=True).splitlines()
    except subprocess.CalledProcessError:
        paths = None
    plan = choose(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'],
                  event.get('inputs', {}).get('validation', 'auto'), paths)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('plan=' + json.dumps(plan, separators=(',', ':')) + '\n')
        output.write('mode=' + plan['mode'] + '\n')
        output.write('matrix=' + json.dumps(plan['matrix'], separators=(',', ':')) + '\n')
        output.write('quality=' + str(plan['quality']).lower() + '\n')
    print(json.dumps(plan))


if __name__ == '__main__':
    main()
