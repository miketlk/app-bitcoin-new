# Liquid application : Integration Guide

- [Liquid application : Integration Guide](#liquid-application--integration-guide)
  - [Applications and Roles](#applications-and-roles)
  - [Interaction Protocol](#interaction-protocol)
  - [Typical Usage Scenarios](#typical-usage-scenarios)
    - [Wallet creation](#wallet-creation)
    - [Receiving crypto assets](#receiving-crypto-assets)
    - [Sending crypto assets](#sending-crypto-assets)
    - [Signing an arbitrary message](#signing-an-arbitrary-message)
  - [Wallet Descriptors](#wallet-descriptors)
  - [PSET as a Merkle Tree](#pset-as-a-merkle-tree)
  - [Important PSET Fields](#important-pset-fields)
    - [Standard fields](#standard-fields)
    - [Hardware wallet extensions](#hardware-wallet-extensions)
  - [Tests and Reference Implementation](#tests-and-reference-implementation)

## Applications and Roles

This is a brief guidance on integration of the Liquid application running on a hardware wallet into signature workflow. In this document, we describe the application running on the **Ledger Nano S** platform of Ledger hardware wallets sharing the same development framework and built-in operating system, BOLOS (also including Nano S Plus and Nano X models).

We assume that normally the Liquid transactions are prepared and managed using a desktop or a mobile application offering rich user interface and in most cases network connection as well. Let's call it the **host app**, or simply **host**, considering its principal role. It could also be called the *companion app* in Ledger's terminology.

The hardware wallet application, called **HWW app** for brevity, is a small program loadable into a specialized digital signature device typically having the form-factor of a USB token with a tiny screen. Such a **HWW device** provides an additional layer of security for the host app by offloading signature and private key management features to a dedicated small computer with strong memory protection capabilities (which the hardware wallet is). The wide range of loadable HWW apps allows operations with many tokens and blockchains. In our case, that is the Liquid Network and the assets it supports.

## Interaction Protocol

The protocol used by the host app to communicate with HWW app is very similar to the widespread ISO/IEC 7816-4 protocol for smart cards. The communication protocol consists of a set of commands that can be used to control and manage HWW app and also the structure of the command/response payloads exchanged between the parties – the Application Protocol Data Unit (APDU).

APDUs are coming in two forms: command APDUs and response APDUs. Command APDUs are sent from a host app to a HWW app and contain the instruction code, parameters, and data. Response APDUs are sent back from a HWW app containing the response data and status code.

In addition, the Event / Commands / Status model is added to make communication process more interactive and allow HWW app having asynchronous responses as it processes lengthy transactions. This feature is implemented by the help of specialized status code `SW_INTERRUPTED_EXECUTION` (`0xE000`). It is returned by HWW app accompanied by appropriate command code and information to signal that it needs something from the host before processing continues. This could be some additional data that is not provided within initial command APDU. Or it could be a piece of HWW app's response if it's too large to fit within a single response block. The host app responses with special *CONTINUE* command `CLA = 0xF8` and `INS = 0x01`, containing the appropriate response.

So, the `SW_INTERRUPTED_EXECUTION` status code could be seen as a kind of backward request from HWW app to the host app. APDU processing may result in many such status codes returned by HWW app before the final result is returned together with `SW_OK` (`0x9000`).

Please see [here](liquid.md) for a detailed specification on the APDU protocol of the HWW app.

## Typical Usage Scenarios

### Wallet creation

When a hardware wallet is used to store a master key, its assistance is typically needed for the host app to create and manage a new wallet on the user's behalf. The host app can use `GET_MASTER_FINGERPRINT` to get master key fingerprint and `GET_EXTENDED_PUBKEY` to derive the public keys associated with the wallet it creates.

For the wallets intended for confidential transactions, let's call them "blinded", the command `LIQUID_GET_MASTER_BLINDING_KEY` allows asking the HWW app to provide the master private blinding key. The HWW app derives it from the seed according to SLIP-0077. A blinding key for a specific scriptPubKey can be obtained using `LIQUID_GET_BLINDING_KEY`.

For the multisig and non-standard wallets, the procedure of wallet creation is a bit more complicated because the HWW app expects such wallets to be registered before use. The HWW app supports `REGISTER_WALLET` command for this purpose. On wallet registration, the host provides a wallet descriptor and all public keys. Once the user approves, the HWW app returns a 32-byte HMAC-SHA256 code to the host. This code should be provided to any future command that makes use of the newly registered wallet.

The HMAC code and complete wallet information should be permanently stored on the host for the whole wallet's lifecycle. No data related to registered wallets is stored on the HWW device itself, and thus there is no limit on the number of registered wallets. But if the HMAC code is lost, the wallet registration must be repeated from scratch.

More information on wallet descriptors and public keys can be obtained [here](liquid_wallet.md).

### Receiving crypto assets

To receive crypto assets, one needs to provide to the sending party a valid receive address. Often, the host software may derive receive addresses on its own from an extended public key. However, the HWW app provides a convenient way to obtain a receive addresses for any wallet it controls by using `GET_WALLET_ADDRESS`. If the wallet is non-standard or multisig, it should be registered beforehand with `REGISTER_WALLET` command. The returned HMAC code should be provided with the address request.

### Sending crypto assets

When the host app is about to sending assets it chooses UTXOs, creates an unsigned transaction and passes it through HWW device to obtain a signature. Depending on the multisig scheme, it could be the only or some number of many signatures required for the validating nodes to approve this transaction. The change addresses needed to compose a transaction can be obtained using `GET_WALLET_ADDRESS` command mentioned in the previous subsection.

The HWW app expects a transaction to be in the standard PSET format, but represented in the form of a Merkle tree, described [here](merkle.md). Choice of Merkle tree representation was dictated by extremely limited memory resources of HWW devices, incapable to store the entire PSET during processing. This format provides a solution allowing stream-like processing of transaction with capability to request random fields. But what is most important, Merkle tree provides a cryptographic proof of transaction immutability during the whole processing.

The signature process is invoked on the side of HWW app with the `SIGN_PSBT` command. The host provides a Merkle tree version of PSET and a reference to the previously registered wallet if it's non-standard or multisig. The HWW app returns a vector of signatures for all the inputs it's able to sign.

### Signing an arbitrary message

The HWW app has a bonus feature allowing to generate a digital signature for the user-provided hash code. In Liquid app it works identically as in Bitcoin app. Not being very popular, nonetheless it finds its use from contracts to software releases. To produce a signature for a message or file, first its SHA256 hash needs to be computed by the host. Then this hash code should be provided to the HWW app as a parameter of the `SIGN_MESSAGE` command together with a BIP-32 path to derive a private key. The private key used to sign the hash never leaves HWW device.

To verify the signature, host app needs to obtain the public key using `GET_EXTENDED_PUBKEY` command. The receiving party should obtain this public key and verify its attribution to the sender via some reliable out-of-band channel.

The algorithm used to compute the digital signature for the user-provided hash code has additional protection against its misuse to sign transactions. Provided hash code is prepended by `"\x18Bitcoin Signed Message:\n"` string and compact length encoding of hash size in bytes. This sentence is then hashed twice with SHA256 to produce the actual hash code for which a digital signature is computed.

## Wallet Descriptors

HWW app uses wallet descriptors based on the specification of Bitcoin wallet descriptors, available [here](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md). However, there are some important differences:

- limited support of script expressions
- `ct()` top-level function used for wallets with blinding key derivation
- keys are moved outside of wallet descriptor and replaced with references @0, @1, @2 ...
- only serialized extended public keys ("xpubs") are supported
- key origin information is compulsory
- it is followed by a `/**` prefix or a `/<NUM;NUM>/*` string, implying the last two steps of derivation

Command APDUs operating with wallet descriptors like `REGISTER_WALLET` are taking a composite parameter named **wallet policy**. The wallet policy includes:

- wallet name (optional)
- wallet descriptor in the form of a Merkle tree, having numbered references instead of actual public keys
- a vector of public keys in the form of a Merkle tree

For the Merkle tree of keys, the host app provides initially just the number of keys and the Merkle tree root (a hash code). As the HWW app progresses through the descriptor, it requests actual keys as needed using an asynchronous mechanism described in the Interaction Protocol section.

The complete specification of wallet descriptors the HWW app supports is provided in the [wallet policy document](liquid_wallet.md).

## PSET as a Merkle Tree

The HWW app uses a special representation of PSET in form of a [Merkle tree](merkle.md). This form was chosen to overcome extreme memory limitations of the Nano S platform. The HWW device is simply unable to hold the whole PSET file in memory, which could be as large as several megabytes. Dividing the PSET into individual fields (tree leafs) the Merkle tree representation guarantees in the same time that none of these fields could be altered or hidden by host since initial commitment was provided (Merkle root).

More precisely, the host app converts a single PSET file into 4 distinct Merkle trees:

- Two Merkle trees corresponding to the global fields of PSET: keys and values
- Merkle tree of a list of inputs of the PSET
- Merkle tree of a list of outputs of the PSET

As for the arguments of `SIGN_PSBT` command, the host app provides 4 roots of these Merkle trees, and the number of elements in each of these tree category (for global fields a single number defines size of trees of keys and values). When the HWW app begins parsing the PSET it starts requesting the actual Merkle tree elements. Each element in the tree of the global fields is an individual PSET field within the global scope. But for the trees of inputs and outputs there is a two-layer structure. An element of these trees is a composite field holding number of elements and two Merkle tree roots. Simply speaking, for PSET inputs and outputs each Merkle tree leaf is a set of another two Merkle trees coding input's or output's key-value records.

## Important PSET Fields

### Standard fields

The HWW app expects that PSET contains all obligatory fields as any entity with Signer role. But besides that, some specific fields are required to verify commitments of confidential transactions. This is especially true because limitations of the Nano S platform do not allow the HWW device to process full-sized rangeproof fields. From the HWW app perspective, all these fields are *mandatory*:

- `PSBT_ELEMENTS_IN_EXPLICIT_VALUE` - this explicit value for the input being spent is always needed unless it could be decoded from non-witness UTXO.
- `PSBT_ELEMENTS_IN_VALUE_PROOF` - a single-value rangeproof, used by HWW app to verify the value commitment of a confidential transaction.
- `PSBT_ELEMENTS_IN_EXPLICIT_ASSET` - this explicit asset for the input being spent is always needed unless it could be decoded from non-witness UTXO.
- `PSBT_ELEMENTS_IN_ASSET_PROOF` - an asset surjection proof used to verify this input's asset commitment.
- `PSBT_OUT_AMOUNT` (`PSBT_OUT_VALUE`) - the output's explicit value, always required, even if blinded value is provided.
- `PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF` - an explicit value rangeproof that proves that the value commitment matches the explicit value.
- `PSBT_ELEMENTS_OUT_ASSET` - the explicit asset tag for this output.
- `PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF` - an asset surjection proof used to verify this output's asset commitment.

At the time of writing, the full PSET specification is available at:

[https://github.com/ElementsProject/elements/blob/master/doc/pset.mediawiki](https://github.com/ElementsProject/elements/blob/master/doc/pset.mediawiki)

### Hardware wallet extensions

Besides standard PSET fields, it is strongly recommended to include supplementary fields specifically added to improve hardware wallet support. They are defined in [ELIP 100](https://github.com/ElementsProject/ELIPs/blob/main/elip-0100.mediawiki).

The global PSET field `PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA` contains the metadata for an asset referenced in some of the transaction's inputs or outputs. This metadata includes asset name, ticker, and precision (decimal digits in fractional part or "satoshis"). The HWW app relies on this information to display rich asset details to the users when they are about to sign the transaction. It is expected that the host downloads the metadata for each asset referenced in PSET and adds the corresponding fields to PSET before sending it to the HWW app for signing.

## Tests and Reference Implementation

The repository of the HWW app includes a set of integration tests available in the directories:

```shell
/tests_liquid
/tests_liquid_main
````

These tests are running on the host system via [pytest](https://pytest.org) using the reference implementation of the client located in the directory:

`/bitcoin_client`

The reference client code is written in Python in the form of a library to be called from tests. Typically, it communicates with the HWW app running on Nano S simulator, Speculos, over sockets. But it can communicate with the real HWW device as well over USB HID. Instructions on running the tests are available in the `README.md` file located inside the test directory.

The reference client implements many important features of the host app, including:

- Top-level implementation of protocol commands: `client.py`
- APDU creation and response parsing: `command_builder.py`
- Handling requests from the HWW app: `client_command.py`
- Transport communication layer: `client_base.py`
- PSET parsing and coding: `pset.py`, `psbt.py`
- Parsing and coding of network transactions: `elements_tx.py`, `tx.py`
- Working with wallet descriptors: `wallet.py`, `descriptor.py`
- Merkle tree implementation used to represent collections of simple or key-value items: `merkle.py`

The easiest way to start studying the reference client code is possibly beginning with `client.py`. It defines the `NewClient` class having the methods named by APDU commands specified [here](liquid.md), each implementing the corresponding command. There is also an abstract interface to these methods defined in the base class, Client, in source file `client_base.py`. It is also a base class for *legacy protocol* implementation `LegacyClient` (`client_legacy.py`). However, this legacy protocol, also named **BTChip** is not currently supported by the Liquid HWW app and is kept for compatibility with Bitcoin app that can be built from the same codebase.
