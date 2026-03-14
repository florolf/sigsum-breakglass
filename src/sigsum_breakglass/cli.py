from os import wait
import sys
import logging
import argparse
import json
import time

from pathlib import Path
from typing import Any, Optional
from nacl.signing import SigningKey, VerifyKey

from . import ssh
from .utils import sha256, b64enc

logger = logging.getLogger(__name__)

def build_parser():
    parser = argparse.ArgumentParser(prog="sigsum-breakglass")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subcommands = parser.add_subparsers(title="subcommands", dest="command", required=True)

    subparser = subcommands.add_parser("make-policy", help="Generate policy from given cosigners")
    subparser.add_argument("breakglass_key", type=Path, help="Breakglass SSH public key file")
    subparser.add_argument("threshold", type=int, help="Threshold for the policy")
    subparser.add_argument("pubkey", nargs="+", type=Path, help="Cosigner SSH public key file")

    subparser = subcommands.add_parser("make-leaf", help="Generate a leaf")
    subparser.add_argument("--file", type=Path, help="File to sign")
    subparser.add_argument("--hash", type=str, help="Hash to sign")
    subparser.add_argument("leaf_key", type=Path, help="SSH public key file for leaf signing key")

    subparser = subcommands.add_parser("make-request", help="Generate signing request from a leaf")
    subparser.add_argument("breakglass_key", type=Path, help="Breakglass SSH public key file")
    subparser.add_argument("leaf", type=Path, help="SSH public key file for leaf signing key")

    subparser = subcommands.add_parser("sign-request", help="Generate a cosignature for a request")
    subparser.add_argument("breakglass_key", type=Path, help="Breakglass SSH public key file")
    subparser.add_argument("signing_key", type=Path, help="SSH public key file for cosignature key")
    subparser.add_argument("request", type=Path, help="Request to sign")

    subparser = subcommands.add_parser("make-proof", help="Generate a proof from a request and cosignatures")
    subparser.add_argument("request", type=Path)
    subparser.add_argument("cosignature", nargs="+", type=Path, help="cosignature files")

    return parser


def do_make_policy(args):
    if args.threshold > len(args.pubkey):
        print(f'threshold {args.threshold} is larger than number of supplied pubkeys ({len(args.pubkey)})', file=sys.stderr)
        sys.exit(1)

    log_key = ssh.Ed25519Key.from_file(args.breakglass_key)
    if log_key.comment:
        print(f'# key name: {log_key.comment}')
    print('log %s' % log_key.pubkey.hex())
    print('')

    names = []
    for path in args.pubkey:
        key = ssh.Ed25519Key.from_file(path)

        name = key.comment
        hexkey = key.pubkey.hex()

        if name is None:
            name = hexkey
        elif ' ' in name:
            print(f'# original name "{name}"')
            name = hexkey

        names.append(name)
        print(f'witness {name} {key.pubkey.hex()}')

    print('')
    print(f'group main {args.threshold} {" ".join(names)}')
    print('quorum main')


def get_root_hash(leaf: dict[str, str]) -> bytes:
    leaf_raw = \
        bytes.fromhex(leaf['checksum']) + \
        bytes.fromhex(leaf['signature']) + \
        bytes.fromhex(leaf['keyhash'])

    return sha256(b'\x00' + leaf_raw)


def make_checkpoint(log_key: ssh.Ed25519Key, root_hash: bytes) -> bytes:
    checkpoint = 'sigsum.org/v1/tree/' + sha256(log_key.pubkey).hex() + '\n'
    checkpoint += '1\n'
    checkpoint += b64enc(root_hash) + '\n'

    return checkpoint.encode()


def do_make_leaf(args):
    if args.file and args.hash:
        print('cannot specify both --file and --hash', file=sys.stderr)
        sys.exit(1)

    if not args.file and not args.hash:
        print('must specify either --file or --hash', file=sys.stderr)
        sys.exit(1)

    agent = ssh.Agent()

    key = ssh.Ed25519Key.from_file(args.leaf_key)

    if args.file:
        data_hash = sha256(args.file.read_bytes())
    else:
        data_hash = bytes.fromhex(args.hash)

    checksum = sha256(data_hash)

    sign_data = b'sigsum.org/v1/tree-leaf\x00' + checksum
    signature = agent.sign(key, sign_data)

    request = {
        'checksum': checksum.hex(),
        'signature': signature.hex(),
        'keyhash': sha256(key.pubkey).hex(),
    }

    print(json.dumps(request, sort_keys = True, indent = True))


def do_make_request(args):
    leaf = json.loads(args.leaf.read_text())

    agent = ssh.Agent()

    key = ssh.Ed25519Key.from_file(args.breakglass_key)
    root_hash = get_root_hash(leaf)
    checkpoint = make_checkpoint(key, root_hash)

    signature = agent.sign(key, checkpoint)

    request = {
        'leaf': leaf,
        'root': {
            'keyhash': sha256(key.pubkey).hex(),
            'signature': signature.hex()
        }
    }

    print(json.dumps(request, sort_keys = True, indent = True))


def do_sign_request(args):
    request = json.loads(args.request.read_text())

    breakglass_key = ssh.Ed25519Key.from_file(args.breakglass_key)
    if request['root']['keyhash'] != sha256(breakglass_key.pubkey).hex():
        print('request keyhash does not match breakglass key', file=sys.stderr)
        sys.exit(1)

    root_hash = get_root_hash(request['leaf'])
    checkpoint = make_checkpoint(breakglass_key, root_hash)

    breakglass_key.verify(checkpoint, bytes.fromhex(request['root']['signature']))

    agent = ssh.Agent()
    signing_key = ssh.Ed25519Key.from_file(args.signing_key)

    timestamp = int(time.time())
    statement = f"cosignature/v1\ntime {timestamp}\n".encode() + checkpoint
    signature = agent.sign(signing_key, statement)

    cosignature = {
        'keyhash': sha256(signing_key.pubkey).hex(),
        'timestamp': timestamp,
        'signature': signature.hex(),
    }

    print(json.dumps(cosignature, sort_keys = True, indent = True))


def do_make_proof(args):
    request = json.loads(args.request.read_text())

    print("version=2")
    print(f"log={request['root']['keyhash']}")
    print(f"leaf={request['leaf']['keyhash']} {request['leaf']['signature']}")
    print('')

    print('size=1')
    print(f'root_hash={get_root_hash(request['leaf']).hex()}')
    print(f'signature={request['root']['signature']}')

    for path in args.cosignature:
        cosig = json.loads(path.read_text())
        print(f'cosignature={cosig["keyhash"]} {cosig["timestamp"]} {cosig["signature"]}')

def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    match args.command:
        case 'make-policy':
            do_make_policy(args)
        case 'make-leaf':
            do_make_leaf(args)
        case 'make-request':
            do_make_request(args)
        case 'sign-request':
            do_sign_request(args)
        case 'make-proof':
            do_make_proof(args)
        case _:
            logging.error(f'unknown command "{args.command}"')
            sys.exit(1)
