#!/usr/bin/env python3
"""Endpoint-only BIP143 check. No FE, ZK, source verifier or funded transactions.

The deterministic keys are PUBLIC TEST KEYS. Never fund their scripts.
The one-input activation/cancellation transactions use fictitious UTXOs.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
from cryptography import __version__ as crypto_version
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def h256(b):
    return sha256(sha256(b).digest()).digest()


def u32(n):
    return n.to_bytes(4, "little")


def u64(n):
    return n.to_bytes(8, "little")


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + n.to_bytes(2, "little")
    raise ValueError("bounded endpoint fixture")


def varbytes(b):
    return compact(len(b)) + b


@dataclass(frozen=True)
class Input:
    outpoint: bytes
    script: bytes = b""
    sequence: int = 0xFFFFFFFD

    def encode(self):
        assert len(self.outpoint) == 36
        return self.outpoint + varbytes(self.script) + u32(self.sequence)


@dataclass(frozen=True)
class Output:
    amount: int
    script: bytes

    def encode(self):
        return u64(self.amount) + varbytes(self.script)


@dataclass(frozen=True)
class Transaction:
    inputs: tuple
    outputs: tuple
    version: int = 2
    locktime: int = 0

    def encode(self):
        return (u32(self.version) + compact(len(self.inputs))
                + b"".join(i.encode() for i in self.inputs)
                + compact(len(self.outputs))
                + b"".join(o.encode() for o in self.outputs)
                + u32(self.locktime))

    def txid_bytes(self):
        return h256(self.encode())


def parse_unsigned(hex_string):
    raw = bytes.fromhex(hex_string)
    pos = 0

    def take(n):
        nonlocal pos
        result = raw[pos:pos+n]
        if len(result) != n:
            raise ValueError("truncated fixture")
        pos += n
        return result

    def number(n):
        return int.from_bytes(take(n), "little")

    def count():
        c = number(1)
        if c < 253:
            return c
        if c == 253:
            return number(2)
        raise ValueError("bounded fixture")

    version = number(4)
    inputs = tuple(Input(take(36), take(count()), number(4))
                   for _ in range(count()))
    outputs = tuple(Output(number(8), take(count()))
                    for _ in range(count()))
    tx = Transaction(inputs, outputs, version, number(4))
    assert pos == len(raw)
    assert tx.encode() == raw
    return tx


def sighash_all(tx, index, witness_script, amount):
    """BIP143 SIGHASH_ALL only; no OP_CODESEPARATOR in supplied script."""
    item = tx.inputs[index]
    preimage = (u32(tx.version)
                + h256(b"".join(i.outpoint for i in tx.inputs))
                + h256(b"".join(u32(i.sequence) for i in tx.inputs))
                + item.outpoint + varbytes(witness_script) + u64(amount)
                + u32(item.sequence)
                + h256(b"".join(o.encode() for o in tx.outputs))
                + u32(tx.locktime) + u32(1))
    return h256(preimage)


def verify(pk, signature, digest):
    try:
        pk.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def main():
    # Public-domain test vector in https://bips.dev/143/, Native P2WPKH.
    vector = parse_unsigned(
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
        "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"
        "0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
        "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
    vector_digest = sighash_all(
        vector, 1, bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"),
        600_000_000)
    assert vector_digest.hex() == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"

    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    keys = [ec.derive_private_key(
        1 + int.from_bytes(sha256(f"PUBLIC FE ENDPOINT TEST KEY {i}".encode()).digest(), "big") % (order-1),
        ec.SECP256K1()) for i in range(3)]
    pubkeys = [k.public_key() for k in keys]
    encoded_keys = [p.public_bytes(serialization.Encoding.X962,
                                  serialization.PublicFormat.CompressedPoint)
                    for p in pubkeys]

    def lock_script(claim):
        # PUSH32(claim commitment), DROP, 3, pk1, pk2, pk3, 3, CHECKMULTISIG.
        return b"\x20" + sha256(claim).digest() + b"\x75\x53" + b"".join(
            b"\x21" + p for p in encoded_keys) + b"\x53\xae"

    source_amount = 1_000_000
    script_a = lock_script(b"claim A: fully serialized assertion placeholder")
    script_b = lock_script(b"claim B: different serialized assertion placeholder")
    parent_input = Input(sha256(b"FICTITIOUS UNFUNDED VAULT").digest() + u32(0))
    activation_a = Transaction((parent_input,),
                              (Output(source_amount, b"\x00\x20" + sha256(script_a).digest()),))
    activation_b = Transaction((parent_input,),
                              (Output(source_amount, b"\x00\x20" + sha256(script_b).digest()),))
    safe_destination = b"\x00\x14" + sha256(b"PUBLIC TEST RECOVERY DESTINATION").digest()[:20]

    def cancel(activation):
        return Transaction((Input(activation.txid_bytes() + u32(0)),),
                           (Output(source_amount - 1000, safe_destination),))

    cancel_a, cancel_b = cancel(activation_a), cancel(activation_b)
    digest_a = sighash_all(cancel_a, 0, script_a, source_amount)
    digest_b = sighash_all(cancel_b, 0, script_b, source_amount)
    # Also isolate outpoint binding while keeping old scriptCode in the digest.
    digest_outpoint_only = sighash_all(cancel_b, 0, script_a, source_amount)
    signatures = []
    for key in keys:
        der = key.sign(digest_a, ec.ECDSA(utils.Prehashed(hashes.SHA256()),
                                        deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        signatures.append(utils.encode_dss_signature(r, min(s, order-s)))

    signatures_repeat = []
    for key in keys:
        der = key.sign(digest_a, ec.ECDSA(utils.Prehashed(hashes.SHA256()),
                                        deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        signatures_repeat.append(utils.encode_dss_signature(r, min(s, order-s)))
    assert signatures_repeat == signatures

    own = [verify(pk, sig, digest_a) for pk, sig in zip(pubkeys, signatures)]
    cross = [verify(pk, sig, digest_b) for pk, sig in zip(pubkeys, signatures)]
    cross_outpoint = [verify(pk, sig, digest_outpoint_only)
                      for pk, sig in zip(pubkeys, signatures)]
    changed_output = replace(cancel_a, outputs=(Output(source_amount-1000,
                              b"\x00\x14"+sha256(b"UNAUTHORIZED DESTINATION").digest()[:20]),))
    bad_output_digest = sighash_all(changed_output, 0, script_a, source_amount)
    unsafe = [verify(pk, sig, bad_output_digest) for pk, sig in zip(pubkeys, signatures)]
    assert activation_a.txid_bytes() != activation_b.txid_bytes()
    assert len({digest_a, digest_b, digest_outpoint_only, bad_output_digest}) == 4
    assert all(own) and not any(cross) and not any(cross_outpoint) and not any(unsafe)

    # One concrete duplicate-signature substitution, not a collusion theorem.
    colluder_bundle = [signatures[0], signatures[1], signatures[0]]
    colluder_checks = [verify(pk, sig, digest_a)
                       for pk, sig in zip(pubkeys, colluder_bundle)]
    assert colluder_checks == [True, True, False]

    result = {
        "scope": "native endpoint only; no FE, source evidence, proof system, Bitcoin VM or chain admission",
        "cryptography_version": crypto_version,
        "bip143_reference_vector": vector_digest.hex(),
        "activation_a_txid": activation_a.txid_bytes()[::-1].hex(),
        "activation_b_txid": activation_b.txid_bytes()[::-1].hex(),
        "cancel_a_sighash": digest_a.hex(),
        "cancel_b_sighash": digest_b.hex(),
        "public_test_keys": [p.hex() for p in encoded_keys],
        "same_message_deterministic_signatures": signatures_repeat == signatures,
        "three_valid_native_signatures": own,
        "cross_claim_replay_accepted": cross,
        "outpoint_only_replay_accepted": cross_outpoint,
        "changed_recipient_accepted": unsafe,
        "duplicate_signature_substitution": colluder_checks,
        "no_fe_implementation": True,
        "no_original_source_or_work_theorem": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
