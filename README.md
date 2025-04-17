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
the course, [available here](https://github.com/gverticale/sdn-vm-polimi).

This VM environment contains a container pre-configured with Python 3, the Ryu framework, NetworkX,
and Mininet, which are necessary to run the project.

To start the application:

1.  Ensure you are running inside the provided Docker container.
2.  Use the `start_controller.sh` script provided in this repository to launch the Ryu controller
    application.
3.  Use the `start_network.sh` script provided in this repository to initialize the Mininet network
    topology. The topology will automatically connect to the running Ryu controller.

## Authors

- Alessandro Modica
- Lorenzo Chiroli
- Letizia Carnevale Giampaolo
- Ronald Cammaroto
