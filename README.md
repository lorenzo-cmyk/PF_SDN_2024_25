# BabyElephantWalk - Software Defined Networking Project (A.Y. 2024/2025)

## Description

This project implements a Ryu SDN controller that distinguishes between high-volume TCP connections
("elephant flows") and low-volume ones ("mice flows") based on transferred data volume.

Mice flows are handled reactively: packets are sent from the switches to the controller, which makes
packet-by-packet forwarding decisions using hop-by-hop routing.

When a connection's transferred volume exceeds a predefined threshold, it becomes an elephant flow.
The controller then installs proactive OpenFlow rules for this specific flow onto all switches along
its path; this offloads forwarding decisions for these large flows directly to the dataplane,
drastically reducing controller load and improving network performance.

## Execution

The controller script is tailored to work inside the specific containerized environment provided for
the course [available here](https://github.com/gverticale/sdn-vm-polimi).

This VM environment contains a container pre-configured with
[Python 3.7](https://github.com/python/cpython), [Ryu Framework](https://github.com/faucetsdn/ryu),
[NetworkX](https://github.com/networkx/networkx), and [Mininet](https://github.com/mininet/mininet),
which are necessary to run the project.

To start the application:

1. Ensure you are running inside the provided Docker container.
2. Use the `start_controller.sh` script provided in this repository to launch the Ryu controller
   application.
3. Use the `start_network.sh` script provided in this repository to initialize the Mininet network
   topology. The topology will automatically connect to the running Ryu controller.

### Optional Requirements

- [FlowManager](https://github.com/martimy/flowmanager): A standalone SDN application that provides
  a nice WebUI to manage the switches connected to the controller. Is also userful to visualize
  graphically the network topology and retrieve the traffic statistics.

  - FlowManager is automatically started by the `start_controller.sh` script if found inside the
    `src/tools/flowmanager` folder.

- [iPerf3](https://github.com/esnet/iperf): The container ships with IPerf2 installed, but iPerf3 is
  better suited for this project thanks to its improved structured output and more detailed
  statistics. Pre-built static binaries are
  [available here](https://github.com/userdocs/iperf3-static/) for both ARM and x86 architectures.
  - A Jupyter Notebook is provided in the `src/tools/iperf3` folder to automatically plot iPerf3
    data. iPerf3 must be run with the `-J` option to generate JSON output, which the notebook can
    then process.

### Documentation

The documentation is available in the `docs` folder. It contains:

- Intermediate and final presentation slides and demo videos.
- Notes on how to validate the project on the physical testbed.

## Authors

- [TheManchineel](https://github.com/TheManchineel)
- [lorenzo-cmyk](https://github.com/lorenzo-cmyk)
- [Leddy02](https://github.com/Leddy02)
- [ronald892](https://github.com/ronald892)
