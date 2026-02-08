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

FAKE_LOG_KEY = SigningKey(bytes(32))

def build_parser():
    parser = argparse.ArgumentParser(prog="sigsum-breakglass")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subcommands = parser.add_subparsers(title="subcommands", dest="command", required=True)

    subparser = subcommands.add_parser("make-policy", help="Generate policy from given cosigners")
    subparser.add_argument("threshold", type=int, help="Threshold for the policy")
    subparser.add_argument("pubkey", nargs="+", type=Path, help="SSH public key file")

    subparser = subcommands.add_parser("make-request", help="Generate a signing request")
    subparser.add_argument("--file", type=Path, help="File to sign")
    subparser.add_argument("--hash", type=str, help="Hash to sign")
    subparser.add_argument("leaf_key", type=Path, help="SSH public key file for leaf signing key")

    subparser = subcommands.add_parser("sign-request", help="Generate a cosignature for a request")
    subparser.add_argument("leaf_key", type=Path, help="SSH public key file for verifying the request")
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

    print('# Dummy log key, corresponding to an all-zero private key')
    print('log %s' % FAKE_LOG_KEY.verify_key.encode().hex())
    print('')

    names = []
    for path in args.pubkey:
        text = path.read_text().strip()
        key = ssh.Ed25519Key.from_line(text)

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


def make_checkpoint(root_hash: bytes) -> bytes:
    checkpoint = 'sigsum.org/v1/tree/' + sha256(FAKE_LOG_KEY.verify_key.encode()).hex() + '\n'
    checkpoint += '1\n'
    checkpoint += b64enc(root_hash) + '\n'

    return checkpoint.encode()


def do_make_request(args):
    if args.file and args.hash:
        print('cannot specify both --file and --hash', file=sys.stderr)
        sys.exit(1)

    if not args.file and not args.hash:
        print('must specify either --file or --hash', file=sys.stderr)
        sys.exit(1)

    agent = ssh.Agent()

    text = args.leaf_key.read_text().strip()
    key = ssh.Ed25519Key.from_line(text)

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


def check_leaf(leaf_key: ssh.Ed25519Key, leaf: dict[str, str]):
    if leaf['keyhash'] != sha256(leaf_key.pubkey).hex():
        print('request keyhash does not match leaf key', file=sys.stderr)
        sys.exit(1)

    leaf_data = b'sigsum.org/v1/tree-leaf\x00' + bytes.fromhex(leaf['checksum'])
    try:
        leaf_key.verify(leaf_data, bytes.fromhex(leaf['signature']))
    except Exception as e:
        print(f'failed to verify leaf signature: {e}', file=sys.stderr)
        sys.exit(1)


def do_sign_request(args):
    request = json.loads(args.request.read_text())

    leaf_key = ssh.Ed25519Key.from_line(args.leaf_key.read_text().strip())
    check_leaf(leaf_key, request)

    agent = ssh.Agent()
    signing_key = ssh.Ed25519Key.from_line(args.signing_key.read_text().strip())

    root_hash = get_root_hash(request)
    checkpoint = make_checkpoint(root_hash)

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

    root_hash = get_root_hash(request)
    checkpoint = make_checkpoint(root_hash)
    signature = FAKE_LOG_KEY.sign(checkpoint).signature

    print("version=2")
    print(f"log={sha256(FAKE_LOG_KEY.verify_key.encode()).hex()}")
    print(f"leaf={request['keyhash']} {request['signature']}")
    print('')

    print('size=1')
    print(f'root_hash={root_hash.hex()}')
    print(f'signature={signature.hex()}')

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
        case 'make-request':
            do_make_request(args)
        case 'sign-request':
            do_sign_request(args)
        case 'make-proof':
            do_make_proof(args)
        case _:
            logging.error(f'unknown command "{args.command}"')
            sys.exit(1)
