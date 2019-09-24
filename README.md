# Purple Protocol
[![Build Status](https://travis-ci.org/purpleprotocol/purple.svg?branch=master)](https://travis-ci.org/purpleprotocol/purple) [![Discord](https://img.shields.io/discord/435827644915777536.svg)](https://discord.gg/UCYWSsd) [![_pdf whitepaper](https://img.shields.io/badge/_pdf-whitepaper-blue.svg)](https://purpleprotocol.org/whitepaper/)

Welcome to the official Rust implementation of the Purple Protocol!

---

Purple is a highly scalable, general-purpose decentralized ledger protocol. It's state of the art algorithms and architectural design potentially allow it to handle thousands of transactions per second which would allow the mainstream use of decentralized ledger technology.

### General purpose
The Purple Protocol is agnostic to the type of applications that can run on it which can be anything from a simple issued asset with no properties to full fledged decentralized insurance schemes and KYC. In fact, it is agnostic even to the programming language used to develop said applications.

### Language agnostic
The Purple Assembly format, also known as `PASM` allows compilers for languages such as C#, Java or Rust to build code native to the Purple Protocol target platform. Any language that targets the [LLVM compiler infrastructure](https://en.wikipedia.org/wiki/LLVM) is potentially supported.

### Consensus
In order to achieve a high transaction throughput, a new consensus mechanism has been devised from scratch by starting from the latest distributed systems and cryptocurrency research. The result is an extension of the Nakamoto Consensus Scheme present in Bitcoin and other cryptocurrencies.

#### Rationale
In traditional Proof of Work systems, the ledger is updated by one randomly chosen "master node" which decides the next state of the ledger. The problem is that this is limited by the current block time which cannot be less than a few seconds.

SSPoW maintains the same scheme of choosing a node by it requiring to provide a valid PoW. The difference is that after a node has been chosen, it can decide more than once the next state of the ledger, without waiting for another valid proof.

In fact, in SSPoW, multiple nodes can do this at the same time by forming a validation pool and executing a second consensus algorithm which is inherently **asynchronous** and is thus much faster.

If too many corrupt nodes enter the validation pool, the asynchronous algorithm will blow up. The trick is that in combination with the first step, the entry rate to the pool can be adjusted by lowering or raising the block time interval.

At the same time, the amount of sets a node is allowed to validate while being in the pool can also be adjusted. In this way, with the right parameters, the system can in theory achieve equilibrium and thus remain operational even in case of attacks such as the dreaded 51% attack.   

For more information on the consensus mechanism, take a look at the [introduction page](https://github.com/purpleprotocol/wiki/wiki/Consensus-Introduction) on the wiki. 
  
### Warning 
All of this is still highly experimental and awaiting to be stress-tested on a large network. Many things can and possibly will still change.

If you want a clear description of the progress so far you can look at the [milestones](https://github.com/purpleprotocol/purple/milestones) section of the repository.

**USE AT YOUR OWN RISK!**
  

## Building
Building the project requires cmake, clang/llvm and the CUDA toolkit. After all dependencies are installed, run:

```
cargo build
```

#### Using docker
A Purple node can also be run from a docker container:

```
docker build .
```

## Running
To run the node in development mode with all logging enabled:

##### Set permission to run the script
```
chmod ug+x ./run_debug.sh
```

##### Run node
```
./run_debug.sh
```