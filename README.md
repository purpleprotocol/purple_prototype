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
  
### Warning 
All of this is still highly experimental and awaiting to be stress-tested on a large network. Many things can and possibly will still change.

If you want a clear description of the progress so far you can look at the [milestones](https://github.com/purpleprotocol/purple/milestones) section of the repository.

**USE AT YOUR OWN RISK!**
  

## Building
Building the project requires cmake, clang/llvm and the CUDA toolkit. Note that building the core requires Rust `>= 1.39.0`. After all dependencies are installed, run:

```
cargo build
```

#### Using docker
A Purple node can also be run from a docker container:

```
docker build -t purple .
```

## Running
After building the docker image, to run the node with all logging enabled:

##### Run node
```
docker run -it purple
```