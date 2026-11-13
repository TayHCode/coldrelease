#!/usr/bin/env python3
import argparse
import fcntl
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

INTERFACE = 'cold.exec/v0'
OK, FAIL, USAGE, TRY_LATER, NO_ANSWER = 0, 1, 2, 75, 125
REPO = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+')
SHA = re.compile(r'[0-9a-f]{40}')
ID = re.compile(r'cbx-[0-9]+-[0-9a-f]+')
VERDICTS = ('pass', 'fail', 'incomplete')
NEXT_STATE = {'queued': 'running', 'running': 'done', 'done': 'done'}


class Usage(Exception):
    pass


class NoAnswer(Exception):
    pass


def env_choice(name, default, allowed):
    value = os.environ.get(name, default)
    if value not in allowed:
        raise Usage(f'{name} must be one of {", ".join(allowed)}, not {value!r}')
    return value


def queue_limit():
    value = os.environ.get('COLD_EXEC_FAKE_QUEUE', '2')
    if not value.isdigit() or int(value) < 1:
        raise Usage(f'COLD_EXEC_FAKE_QUEUE must be a positive integer, not {value!r}')
    return int(value)


@contextmanager
def state():
    value = os.environ.get('COLD_EXEC_FAKE_STATE')
    if not value:
        raise Usage('set COLD_EXEC_FAKE_STATE to a directory the fake may write')
    root = Path(value)
    (root / 'jobs').mkdir(parents=True, exist_ok=True)
    (root / 'vms').mkdir(exist_ok=True)
    with open(root / 'lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield root


def new_id():
    return f'cbx-{int(time.time())}-{secrets.token_hex(3)}'


def now_iso():
    return datetime.now(UTC).isoformat(timespec='seconds')


def emit(record):
    print(json.dumps(record, sort_keys=True))


def load(path, what):
    if not path.is_file():
        raise NoAnswer(f'no {what} {path.stem}')
    return json.loads(path.read_text(encoding='utf-8'))


def save(path, record):
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def submit(args):
    if not REPO.fullmatch(args.repo):
        raise Usage(f'--repo must be OWNER/REPO, not {args.repo!r}')
    if not SHA.fullmatch(args.sha):
        raise Usage(f'--sha must be a full 40-character lowercase commit, not {args.sha!r}')
    verdict = env_choice('COLD_EXEC_FAKE_VERDICT', 'pass', VERDICTS)
    limit = queue_limit()
    with state() as root:
        jobs = [json.loads(p.read_text(encoding='utf-8')) for p in (root / 'jobs').glob('*.json')]
        if sum(job['state'] != 'done' for job in jobs) >= limit:
            print(f'fake: the queue holds {limit} unfinished jobs; try again later', file=sys.stderr)
            return TRY_LATER
        job = {'id': new_id(), 'seq': len(jobs), 'repo': args.repo, 'sha': args.sha, 'ttl': args.ttl, 'offline': args.offline,
                   'verdict': verdict, 'state': 'queued', 'submitted_at': now_iso()}
        save(root / 'jobs' / f"{job['id']}.json", job)
    emit({'id': job['id'], 'state': job['state']})
    return OK


def advance(root, job_id):
    if not ID.fullmatch(job_id):
        raise NoAnswer(f'no job {job_id}')
    path = root / 'jobs' / f'{job_id}.json'
    job = load(path, 'job')
    others = (load(p, 'job') for p in (root / 'jobs').glob('*.json'))
    if job['state'] == 'queued' and any(o['seq'] < job['seq'] and o['state'] != 'done' for o in others):
        return job
    if job['state'] != 'done':
        job['state'] = NEXT_STATE[job['state']]
        if job['state'] == 'done':
            job['receipt'] = receipt_for(root, job)
        save(path, job)
    return job


def receipt_for(root, job):
    log = root / 'jobs' / f"{job['id']}.log"
    log.write_text(f"fake backend: {job['repo']}@{job['sha']} -> {job['verdict']}\n", encoding='utf-8')
    receipt = {'schema': 'coldbox.receipt/v1', 'id': job['id'], 'mode': 'submit', 'host': 'fake', 'repo': job['repo'],
                   'sha': job['sha'], 'verdict': job['verdict'], 'checks': [], 'started_at': job['submitted_at'], 'log': str(log),
                   'vm': {'name': job['id'], 'image': 'fake', 'ttl_seconds': job['ttl'], 'offline': job['offline'],
                           'destroyed': True, 'destroyed_at': now_iso()}}
    if job['verdict'] == 'incomplete':
        receipt['error'] = 'fake: the backend gave no answer'
    else:
        receipt.update(exit=0 if job['verdict'] == 'pass' else 1, tests_ran=1, tests_source='junit')
    return receipt


def status(args):
    with state() as root:
        job = advance(root, args.id)
    emit({'id': job['id'], 'state': job['state']})
    return OK


def receipt(args):
    with state() as root:
        job = advance(root, args.id)
    if job['state'] != 'done':
        print(f"fake: {job['id']} is {job['state']}; try again later", file=sys.stderr)
        return TRY_LATER
    emit(job['receipt'])
    return {'pass': OK, 'fail': FAIL}.get(job['receipt']['verdict'], NO_ANSWER)


def vm_dir(root, name):
    path = root / 'vms' / name
    if not ID.fullmatch(name) or not path.is_dir():
        raise NoAnswer(f'no VM named {name}')
    left = load(path / '.vm.json', 'VM')['expires'] - time.time()
    if left <= 0:
        shutil.rmtree(path)
        raise NoAnswer(f'{name} has expired and was deleted')
    return path, left


def vm_up(args):
    with state() as root:
        name = new_id()
        (root / 'vms' / name).mkdir()
        save(root / 'vms' / name / '.vm.json', {'name': name, 'expires': time.time() + args.ttl, 'offline': args.offline})
    print(name)
    return OK


def vm_exec(args):
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        raise Usage('give a command after the VM name')
    with state() as root:
        path, left = vm_dir(root, args.name)
    try:
        process = subprocess.Popen(command, cwd=path, start_new_session=True)
    except FileNotFoundError:
        print(f'fake: {command[0]}: command not found', file=sys.stderr)
        return 127
    try:
        return process.wait(timeout=left)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise NoAnswer(f'{args.name} reached its TTL') from None


def vm_down(args):
    with state() as root:
        shutil.rmtree(vm_dir(root, args.name)[0])
    print(f'fake: {args.name} deleted', file=sys.stderr)
    return OK


def version(_args):
    emit({'interface': INTERFACE, 'backend': 'fake'})
    return OK


def parser():
    top = argparse.ArgumentParser(prog='exec_fake.py', description=f'Fake {INTERFACE} backend for consumer tests.')
    sub = top.add_subparsers(dest='cmd', required=True)
    sub.add_parser('version').set_defaults(run=version)
    p = sub.add_parser('submit')
    p.add_argument('--repo', required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--ttl', type=int, default=3600)
    p.add_argument('--offline', action='store_true')
    p.set_defaults(run=submit)
    for name, run in (('status', status), ('receipt', receipt)):
        p = sub.add_parser(name)
        p.add_argument('id')
        p.set_defaults(run=run)
    vm = sub.add_parser('vm').add_subparsers(dest='action', required=True)
    p = vm.add_parser('up')
    p.add_argument('--ttl', type=int, default=7200)
    p.add_argument('--offline', action='store_true')
    p.set_defaults(run=vm_up)
    p = vm.add_parser('exec')
    p.add_argument('name')
    p.add_argument('command', nargs=argparse.REMAINDER)
    p.set_defaults(run=vm_exec)
    p = vm.add_parser('down')
    p.add_argument('name')
    p.set_defaults(run=vm_down)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    if getattr(args, 'ttl', 1) < 1:
        print('fake: --ttl must be at least 1', file=sys.stderr)
        return USAGE
    try:
        return args.run(args)
    except Usage as error:
        print(f'fake: {error}', file=sys.stderr)
        return USAGE
    except NoAnswer as error:
        print(f'fake: {error}', file=sys.stderr)
        return NO_ANSWER


if __name__ == '__main__':
    sys.exit(main())
