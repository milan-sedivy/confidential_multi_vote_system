### Disclaimer: The code in this repository is not considered secure. The only purpose of this repository is to demonstrate principles of a protocol outlined in my thesis. 

# Confidential electronic shareholder meeting voting scheme
## Introduction
This repository contains my master's thesis project, which builds upon the [Practical Multi-Candidate Election System (Baudron et al., 2001)](https://people.csail.mit.edu/rivest/voting/papers/BaudronFouquePointchevalPoupardStern-PracticalMultiCandidateElectionSystem.pdf).
The goal of the expanded protocol is twofold:
- To mask voter identity without requiring unique proof of identity for each vote, and to do so without complex zero-knowledge proofs.
- To extend the original scheme to support not only multi-candidate voting but also multiple votes per voter, simulating a shareholder meeting scenario.

Note:
Due to the public nature of the final results, this scheme is only able to preserve the anonymity of minority shareholders.
The voting patterns of majority shareholders may be inferred, especially when their voting power significantly influences the outcome.

### Identity Masking Using ElGamal Chameleon Keys
The first goal is achieved by using an ElGamal signature scheme that enables the creation of what this protocol refers to as "chameleon keys". 

The voter initially proves their identity to a Certification Authority (CA). Once verified, the CA issues a certificate that includes the voter's encrypted ElGamal public key along with the number of votes (shares).
To never expose the actual ElGamal key pair to the CA a simple cut-and-choose technique can be used - for example, the voter 
generates 10 certificates, and the CA randomly selects 9 to be decrypted for verification, blindly signing the remaining one (if and only if the other 9 were correct). This ensures the validity of the rights 
to vote without exposing the original key pair and other details.

The original private key remains hidden, and new ElGamal key pairs can be generated from it inside a Trusted Execution Environment (TEE).
The resulting public keys are sent to the tally server, which uses them to verify incoming votes. The corresponding private keys, used to sign the votes, remain known only to the voter (assuming proper attestation of the TEE).

### Supporting Multiple Votes Using Base-3 Encoding

The second goal is accomplished by encoding votes in base-3. Each voting option is encoded positionally in the digits of a base-3 number, each digit represents:

- Yes
- No
- Abstain

This encoding enables voters to express multiple distinct choices in a single vote and can be further extended to fit the needs of specific voting processes.
Each vote, therefore, represents a permutation of the voter's selections.

By using these techniques, all core properties of the original electronic voting scheme remain intact. The diagram below provides a high-level overview of the protocol as implemented in this repository.
<div style="text-align: center;">
<img src="img/protocol.svg" alt="High-level overview of the protocol">
</div>

## How to run
The configuration files needed to run the example are already present in the repository. To see a simulation of the protocol
just run these applications from the root directory in the following order:
1) Run the `voting_server` - this is the owner of the voting tally. It accepts encrypted vote from the `client_app`.
```
cargo run --bin voting_server
```
2) Run the `pem_server` - this is the "trusted dealer" in the current setup and is a representation of what would be running in a TEE.
```
cargo run --bin pem_server
```
3) Run the `client_app` - this is your "voting application" it encodes and encrypts your vote for you
```
cargo run --bin client_app 
```
4) Once the votes were cast you can run the `key_share_holders` executable - this will perform the threshold decryption of the encrypted tally 
```
cargo run --bin key_share_holders
```

## Final notes
This codebase was written quickly and with minimal attention to code quality, security, or optimization.
Its sole purpose is to demonstrate the protocol described in my thesis.

It is not suitable for use in any context where secure coding standards are required.
Use at your own risk - none of the implementation should be considered production-ready.