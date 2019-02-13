# purple-rs
[![Build Status](https://travis-ci.org/purpleprotocol/purple.svg?branch=master)](https://travis-ci.org/purpleprotocol/purple-rs)
[![Discord](https://img.shields.io/discord/435827644915777536.svg)](https://discord.gg/UCYWSsd)
[![_pdf whitepaper](https://img.shields.io/badge/_pdf-whitepaper-blue.svg)](https://purpleprotocol.org/whitepaper/)

A full Rust re-write of the Purple Protocol. This is intended to be the final and the most performant implementantion of the protocol.

Purple is a decentralized, programmable, multi-asset blockchain protocol that is capable of processing a large volume of transactions with ease. 

This is done by using a novel consensus algorithm which leverages the properties of semi-synchronous systems in order to balance scalability with security.



## Building
Building the project requires the latest rust nightly toolchain and cmake. After all dependencies are installed, run:

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