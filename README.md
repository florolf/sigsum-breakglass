# sigsum-breakglass

## Rationale

When using [Sigsum](https://www.sigsum.org/), you are making yourself dependent on third parties (like the log service and the witnesses). This is the whole point, but in some applications you might want to add an escape hatch for cases like a sufficient number of those parties being unavailable at a critical point in time when you really need to sign something or having failed to keep an offline verifier in sync and its policy having become unsatisfiable.

However, adding an escape hatch is dangerous since it circumvents the transparency mechanism, so it shouldn't just be a single magic signing key you keep under your pillow. Ideally, you'd want some kind of threshold scheme where you can be sure that at least one of the involved parties will publicly raise an alarm about being asked to trigger such an escape hatch.

Threshold signature schemes exist - even ones like [FROST](https://www.rfc-editor.org/rfc/rfc9591.html) that look like regular Ed25519 signatures from the outside. But it turns out this is an unnecessary complication: The Sigsum verifier you already have kind of already implements a threshold signature scheme through the cosignature quorum rules. By generating a special policy and checking it as a fallback after your regular policy check fails, you can get "breakglass signatures" almost for free.

`sigsum-breakglass` is a tool for managing such a mechanism.

## Usage
### Step 0: Pick your key custodians

Pick the people you'd like to rely on for the threshold signatures. Each of them needs to generate an Ed25519 key and supply the public key to you in the standard OpenSSH format (i.e. `ssh-ed25519 AAAA...`). `sigsum-breakglass` uses an SSH agent for all signature operations, so hardware-backed keys are possible if there is corresponding agent support. Note that `sk-ssh-ed25519` (i.e. FIDO tokens) will *not* work as those aren't plain Ed25519 signatures we can reuse in a different protocol.

You will also need to tell them about the signing pubkey (i.e. the `-k` argument to `sigsum-verify`) you intend to use.

### Step 1: Generate a policy

First, install this package into a virtualenv using whatever tool you like, e.g. `pip install git+https://github.com/florolf/sigsum-breakglass`.

The, use the `make-policy` sub-command to generate a policy with a threshold and a given set of custodians:

```
$ sigsum-breakglass make-policy 2 custodian1.pub custodian2.pub custodian3.pub > policy
$ cat policy
# Dummy log key, corresponding to an all-zero private key
log 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29

witness custodian1 3311d6d2cf54689d0c714566032fb3e7e22bc09a81203dbe42806f5a96a1eb10
witness custodian2 1d0c7f2a8885d27f3a6edf87bd500cb92ec444c745dce08d7400e777b2e990a9
witness custodian3 b954ca8c73ae052f379a4b342a113ef63e4e6754a31c1b42c8ec4542884e4679

group main 2 custodian1 custodian2 custodian3
quorum main
```

The witness names are derived from the comment field of the pubkey file if it exists and is a valid witness name according to the [policy specification](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/v0.14.0/doc/policy.md). Otherwise the hex-encoded public key is also used as the name.

Use this policy as the fallback policy in your verifier.

### Step 2: Generate a signing request

If you need to make use of the breakglass mechanism, generate a signing request based on your regular signing key (which needs to be present in the SSH agent determined by the `SSH_AUTH_SOCK` environment variable) and the data to be signed, as with a regular `sigsum-submit` operation:

```
$ sigsum-breakglass make-request --hash 6f024c51ca5d0b6568919e134353aaf1398ff090c92f6173f5ce0315fa266b93 signing-key.pub > request.json
$ cat request.json
{
 "checksum": "465283372667265e1f9515813be447692a3ab09f879bb6ded5a826872550fd39",
 "keyhash": "e3e148408dee5d1e71dbdfc08f5b0373da0ceb55d8e7f8ecc64c66794c5a5e5b",
 "signature": "45565601e0c789fdbc806f7b7e3c7910cf68904a18261c991546df057faff869c0ebeeb789faefee68a1e7be7cf1e519c0f697f6f2b1208b759cbb4b3a30120c"
}
```

You can either give the SHA256 hash of the message to be signed directly (using `--hash` as shown above) or by using `--file`, which hashes the given file to produce the hash.

Distribute this request to your custodians.

### Step 3: Generate cosignatures

Each custodian now carefully considers whether to cosign this request. While `sign-request` verifies the leaf signature made in step 2, they might still want to reach out to you through some other channel to see what is going on or request the signed data so they can publish it somewhere.

Once they are ready to cosign the request, they execute:

```
$ sigsum-breakglass sign-request signing-key.pub custodian1.pub request.json > cosig1.json
$ cat cosig1.json
{
 "keyhash": "2017a6fee25d302f100e9f2e31a3bdc0f0c68b4d5b380ac5f346c0869e96ac91",
 "signature": "22b6c64f0782f6c4ecf27a98cbe07c1c0ccab16abab545d824c3281ed53fd77fe3c26d46eb361c10f09f82e797c51a4be0cd5bd3fa0b77903560ecfa26291105",
 "timestamp": 1770570534
}
```

Where `signing-key.pub` is the public key corresponding to the leaf signing key used in step 2 and `custodian1.pub` is their cosigning public key (the latter needs to be present in their SSH agent).

They then return the generated data back to you.

### Step 4: Merge everything into a proof

Use the original request and the cosignatures to construct a faux Sigsum proof:

```
$ sigsum-breakglass make-proof request.json cosig1.json cosig2.json > proof
$ cat proof
version=2
log=139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070
leaf=e3e148408dee5d1e71dbdfc08f5b0373da0ceb55d8e7f8ecc64c66794c5a5e5b 45565601e0c789fdbc806f7b7e3c7910cf68904a18261c991546df057faff869c0ebeeb789faefee68a1e7be7cf1e519c0f697f6f2b1208b759cbb4b3a30120c

size=1
root_hash=5e90f2dadc86a17e8522075d76b91d0cd2e23907b9bc07d990a7ebfd6b29316d
signature=1101cdcd2a6b95bfa6faf598d1db9fbadb27da44a4e2b96f1341b84b561e0cebe4df826f3f85aaf0b49b32958870d9757050c01981e357ca4ee31dbfa1d23a03
cosignature=2017a6fee25d302f100e9f2e31a3bdc0f0c68b4d5b380ac5f346c0869e96ac91 1770570534 22b6c64f0782f6c4ecf27a98cbe07c1c0ccab16abab545d824c3281ed53fd77fe3c26d46eb361c10f09f82e797c51a4be0cd5bd3fa0b77903560ecfa26291105
cosignature=1ad6c7063443ee851dcff1aa2a35ee3740c8ed0e3ba7b42d9f5976fbcd719fbe 1770570718 f94e8cd7bc9ed799a402a0d168ddb1859fc232394b96f0170d4692747b7584a27c113abaa614a8b588a9f8dbf5da0eee25de5f659c1ff098727b8b0b4d15150a
```

In this example, we were only able to obtain two cosignatures, but this is enough according to the policy. You can now check that this proof verifies using `sigsum-verify`:

```
$ echo -n '6f024c51ca5d0b6568919e134353aaf1398ff090c92f6173f5ce0315fa266b93' | sigsum-verify -k signing-key.pub -p policy --raw-hash proof
$ echo $?
0
```

## Internals

There is not much magic going on here. We fake a single-entry log since the verifier is normally stateless anyway, so we can also do this more than once. The log key is a hardcoded dummy key since making it changeable wouldn't add any useful functionality or security.
