rust_ofp [![Build Status](https://travis-ci.org/baxtersa/rust_ofp.svg?branch=master)](https://travis-ci.org/baxtersa/rust_ofp)
===
OpenFlow 1.0 protocol and controller in Rust.
---
`rust_ofp` aims to implement the OpenFlow1.0 protocol, for purposes of prototyping SDN systems in Rust. In the future, this may grow to support other OpenFlow specifications (namely 1.3), and others protocols entirely.

I'm drawing heavily on inspiration and code structure from the [frenetic-lang](https://github.com/frenetic-lang) project, due to my familiarity with it. I hope that Rust will enable a more natural implementation of the low-level protocol than OCaml + CStructs, and true parallelism will allow for higher controller performance and a simpler event loop.

Building
---
`rust_ofp` is composed of a Rust library implementing the OpenFlow 1.0 protocol, and a `rust_ofp_controller` binary that currently acts as little more than an echo server for SDN configurations. It can be built and run by the normal means for Rust projects.
```bash
cd path/to/rust_ofp
cargo build
cargo run
```

Testing
---
I'm performing all correctness evaluation in [mininet](https://mininet.org) for the time being. Mininet offers quick feedback, as much scalability as I need for now, and should properly support OpenFlow 1.0 (and other protocols). There is no reason correctness in mininet shouldn't transfer to physical hardware as well, and maybe one day I'll get around to testing out that hypothesis.

Anyway, testing the controller binary is pretty straightforward, assuming mininet is installed.
In one terminal
```bash
cd path/to/rust_ofp
cargo run
```
In another terminal
```bash
sudo  mn --controller=remote
```
The terminal running `rust_ofp_controller` will occasionally print some things out, logging a rough idea of the types of messages it receives, and behaviors it performs.

The mininet terminal should launch an interactive shell with the typical mininet utilities. Soon, the controller may even install forwarding rules on switches that you'll be able to investigate with `ovs-ofctl` queries!
