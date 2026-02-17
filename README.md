# sigsum-breakglass

## Rationale

When using [Sigsum](https://www.sigsum.org/), you are making yourself dependent on third parties (like the log service and the witnesses). This is the whole point, but in some applications you might want to add an escape hatch for cases like a sufficient number of those parties being unavailable at a critical point in time when you really need to sign something or having failed to keep an offline verifier in sync and its policy having become unsatisfiable.

However, adding an escape hatch is dangerous since it circumvents the transparency mechanism, so it shouldn't just be a single magic signing key you keep under your pillow. Ideally, you'd want some kind of threshold scheme where you can be sure that at least one of the involved parties will publicly raise an alarm about being asked to trigger such an escape hatch.

Threshold signature schemes exist - even ones like [FROST](https://www.rfc-editor.org/rfc/rfc9591.html) that look like regular Ed25519 signatures from the outside. But it turns out this is an unnecessary complication: The Sigsum verifier you already have kind of already implements a threshold signature scheme through the cosignature quorum rules. By generating a special policy and checking it as a fallback after your regular policy check fails, you can get "breakglass signatures" almost for free.

`sigsum-breakglass` is a tool for managing such a mechanism.

## Usage
### Step 1: Generate a breakglass key

Generate a specific Ed25519 key that you will use to authorize breakglass operations. This key can and should be stored offline - hopefully you'll never have to use it. `sigsum-breakglass` uses an SSH agent for all its signature operations (including the ones described below), so hardware-backed keys are possible if there is corresponding agent support. Note that `sk-ssh-ed25519` (i.e. FIDO tokens) will *not* work as those aren't plain Ed25519 signatures we can reuse in a different protocol.

### Step 2: Pick your key custodians

Pick the people you'd like to rely on for the threshold signatures. Each of them needs to generate an Ed25519 key and supply the public key to you in the standard OpenSSH format (i.e. `ssh-ed25519 AAAA...`).

You will also need to tell them the public key of the breakglass key you generated in step 1.

### Step 3: Generate a policy

First, install this package into a virtualenv using whatever tool you like, e.g. `pip install git+https://github.com/florolf/sigsum-breakglass`.

The, use the `make-policy` sub-command to generate a policy with a threshold and a given set of custodians:

```
$ sigsum-breakglass make-policy 2 custodian1.pub custodian2.pub custodian3.pub > policy
$ cat policy
# key name: breakglass
log 7e55283748388e2fa565346516d848ef1195cad5c83816a4b6e24344cfc717e9

witness cosigner1 0356a86448e731c962782b30563d9d5c807f7956c4c361cf48ac75c6bd7fce0f
witness cosigner2 364ced2caf85261de3c91170f137c0bf8688fda3293372d66f02d6b7f4bab79c
witness cosigner3 ce80e6540b37b34c3b15a574ad82e1ebb5b7cae54f5335fb9fa960f5b89dd660

group main 2 cosigner1 cosigner2 cosigner3
quorum main
```

The witness names are derived from the comment field of the pubkey file if it exists and is a valid witness name according to the [policy specification](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/v0.14.0/doc/policy.md). Otherwise the hex-encoded public key is also used as the name.

You can either use this policy as a separate fallback policy in your verifier or merge it with your regular Sigsum policy. There are trade-offs to both options, which are discussed below.

### Step 3: Generate a pseudo-leaf

Generate a leaf data structure using your regular artifact signing key - this is exactly equivalent to the leaf data structure that `sigsum-submit` generates. Your signing key needs to be present in the SSH agent determined by the `SSH_AUTH_SOCK` environment variable.

```
$ sigsum-breakglass make-leaf --hash 6f024c51ca5d0b6568919e134353aaf1398ff090c92f6173f5ce0315fa266b93 signing-key.pub > leaf.json
$ cat leaf.json
{
 "checksum": "465283372667265e1f9515813be447692a3ab09f879bb6ded5a826872550fd39",
 "keyhash": "b9b5ca4ef790ee2371cf51e787a702545e4328f5aa7575ff8baf162af7446f7c",
 "signature": "078335c18fb08488292ccc45a175bf23ab720c888d0ca5c55eea52289696acb3cfe3a723de5eb1e685d6b44a0d2021dc35d5d46ccf9f9a9fd5abf3cabfc9ba03"
}
```

### Step 4: Generate a signing request

Using your breakglass key, transform the leaf into a signing request. This is a separate step so that it can optionally be done on another machine.

```
$ sigsum-breakglass make-request breakglass.pub leaf.json > request.json
$ cat request.json
{
 "leaf": {
  "checksum": "465283372667265e1f9515813be447692a3ab09f879bb6ded5a826872550fd39",
  "keyhash": "b9b5ca4ef790ee2371cf51e787a702545e4328f5aa7575ff8baf162af7446f7c",
  "signature": "078335c18fb08488292ccc45a175bf23ab720c888d0ca5c55eea52289696acb3cfe3a723de5eb1e685d6b44a0d2021dc35d5d46ccf9f9a9fd5abf3cabfc9ba03"
 },
 "root": {
  "keyhash": "415e81ad656a4d1bd36f8f8d07703ed2bf0d00bf9e1a7e5c1f3fa2f1a90e7e61",
  "signature": "69e5d513350061558350726bb8208e4801ca2a0e04599bf325a00a3566001818d64ceff441814911ea9e9a8920dab43848fc2cbb5aed01a51fd149c55c005501"
 }
}
```

Distribute this request to your custodians.

### Step 5: Generate cosignatures

Each custodian now carefully considers whether to cosign this request. While `sign-request` verifies the root signature made in step 3, they might still want to reach out to you through some other channel to see what is going on or request the signed data so they can publish it somewhere.

Once they are ready to cosign the request, they execute:

```
$ sigsum-breakglass sign-request breakglass.pub custodian1.pub request.json > cosig1.json
$ cat cosig1.json
{
 "keyhash": "f5762bab89791fd55deb53fa2faec246ef03f2d823ba276237612cb6ec55969a",
 "signature": "39d88fc30e8a1df0df5c7b339fffbe1e1f34f1f3b67885db4ef47248f4f90dd77fe070ecefb8e9eba0a2d63781a05b2a7e18b96dfc9577478f2e4dc01e7f1005",
 "timestamp": 1771286008
}
```

Where `breakglass.pub` is the breakglass public key from step 1 and `custodian1.pub` is their cosigning public key (the latter needs to be present in their SSH agent).

They then return the generated data back to you.

### Step 6: Merge everything into a proof

Use the original request and the cosignatures to construct a faux Sigsum proof:

```
$ sigsum-breakglass make-proof request.json cosig1.json cosig2.json > proof
$ cat proof
version=2
log=415e81ad656a4d1bd36f8f8d07703ed2bf0d00bf9e1a7e5c1f3fa2f1a90e7e61
leaf=b9b5ca4ef790ee2371cf51e787a702545e4328f5aa7575ff8baf162af7446f7c 078335c18fb08488292ccc45a175bf23ab720c888d0ca5c55eea52289696acb3cfe3a723de5eb1e685d6b44a0d2021dc35d5d46ccf9f9a9fd5abf3cabfc9ba03

size=1
root_hash=12594afb57e40a283bd03afac74641a032065cd59e098278920f55dae9d6f505
signature=69e5d513350061558350726bb8208e4801ca2a0e04599bf325a00a3566001818d64ceff441814911ea9e9a8920dab43848fc2cbb5aed01a51fd149c55c005501
cosignature=f5762bab89791fd55deb53fa2faec246ef03f2d823ba276237612cb6ec55969a 1771286008 39d88fc30e8a1df0df5c7b339fffbe1e1f34f1f3b67885db4ef47248f4f90dd77fe070ecefb8e9eba0a2d63781a05b2a7e18b96dfc9577478f2e4dc01e7f1005
cosignature=500dacf19d1b689f7bf2641283bdda2e37b568d12a420145eaa095743c6a7eb2 1771286014 abf47128ba667057037124abf1c620ed912c2e1ac8921739094ec8ee19f1483f8132eb9f660a4000493ea8ee7502f13bb836486c45c5869d50015e169b49030f
```

In this example, we were only able to obtain two cosignatures, but this is enough according to the policy. You can now check that this proof verifies using `sigsum-verify`:

```
$ echo -n '6f024c51ca5d0b6568919e134353aaf1398ff090c92f6173f5ce0315fa266b93' | sigsum-verify -k signing-key.pub -p policy --raw-hash proof
$ echo $?
0
```

## Design considerations

There is not much magic going on here. We fake a single-entry log since the verifier is normally stateless anyway, so we can also do this more than once.

Previously we didn't have a separate breakglass key, but rather used a dummy key and relied on the leaf signature key itself for authentication towards the cosigners. However, this has downsides when merging the breakglass cosigners into the main policy used by the application (see below). Additionally, this meant an attacker could have triggered a breakglass announcement by just reusing a regular logged signature and submitting it to the cosigners (if they just relied on the signature as a means for authenticating a breakglass request and not reached out to the first party out-of-band), which could be used to cause confusion.

## Policy considerations

There are two ways to integrate `sigsum-breakglass` into the verification process: Running a fallback verification step or merging the policy with your regular one.

Running a fallback verification step means first checking a proof against your regular policy. If that fails, you run the verifier again with the breakglass policy produced in step 3 above. The advantage is that this clearly separates both domains both cryptographically and conceptually (when using this as part of a firmware update mechanism, the device could display a warning when the breakglass mechanism gets triggered). The downside is that this is an extra step, which might be tedious in flows where people are manually verifying proofs. Furthermore, depending on the application, it could be seen as slightly "backdoorsy" and the less-well-trodden path might be brittle when the system gets modified.

Another approach is to merge both policies by adding the breakglass dummy log and the breakglass cosigners as another toplevel group to the main policy. E.g. in the case of the above example and the `sigsum-generic-2025-1` named policy:

```
log 0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25 https://seasalp.glasklar.is
log f00c159663d09bbda6131ee1816863b6adcacfe80b0b288000b11aba8fe38314 https://ginkgo.tlog.mullvad.net

witness witness.glasklar.is            b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536
witness witness.mullvad.net            15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad
witness tillitis.se/tillitis-witness-1 076be8c9ee7ea60916f0df3608c945d7730082ecb37749dad2c9ed339fea770c

group sigsum-generic-2025-1 2 witness.glasklar.is witness.mullvad.net tillitis.se/tillitis-witness-1

# breakglass
log 7e55283748388e2fa565346516d848ef1195cad5c83816a4b6e24344cfc717e9

witness cosigner1 0356a86448e731c962782b30563d9d5c807f7956c4c361cf48ac75c6bd7fce0f
witness cosigner2 364ced2caf85261de3c91170f137c0bf8688fda3293372d66f02d6b7f4bab79c
witness cosigner3 ce80e6540b37b34c3b15a574ad82e1ebb5b7cae54f5335fb9fa960f5b89dd660

group breakglass 2 cosigner1 cosigner2 cosigner3

group quorum-rule any sigsum-generic-2025-1 breakglass

quorum quorum-rule
```

This has the advantage of being completely contained in the regular Sigsum verification flow and being very upfront about the breakglass mechanism in the policy you are distributing/people will look at.

However, since a Sigsum verifier considers all logs in a given policy to be equal, this opens up a potential vector of attack: If somebody (either you or an attack who has stolen your breakglass key) can convince the regular witnesses to cosign a breakglass checkpoint, they will end up with a valid proof that will stay secret (since nobody can monitor the fake breakglass log and unlike the breakglass cosigners which are by definition required to announce their signature operations publicly, regular witnesses are normally silent).

One way this could happen is if enough of the regular witnesses in your policy are participating in the [witness network](https://witness-network.org/) - an attacker could simply submit the breakglass log key for participation.
