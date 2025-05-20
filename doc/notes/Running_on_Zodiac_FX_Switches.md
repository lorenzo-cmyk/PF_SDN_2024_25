# Running on Zodiac FX Switches

This section details specific considerations and workarounds required when running the project on
**Zodiac FX** switches.

## Project Requirement and Hardware Limitations

Project specifications mandate that all network traffic for a TCP connection must transit through
the control plane via the SDN controller _before_ the connection is promoted to an "elephant flow."

On Zodiac FX hardware, this requirement leads to significant stability issues, including:

- Sudden reboots of the switch.
- Packet loss occurring even before packets reach the SDN controller.

These issues appear to be specific to how the Zodiac FX hardware handles traffic routed to its
control plane under these conditions.

## Workaround for iPerf3 Measurements

To enable stable `iPerf3` measurements despite the aforementioned hardware limitations, the
following workarounds were found to be necessary:

1. **Limit TCP Maximum Segment Size (MSS) to 512 Bytes:**

   - Packets exceeding this size (512B) are consistently dropped before reaching the controller,
     irrespective of the packets per second (PPS) rate.

2. **Limit Bandwidth to 128 kbps (approximately 31.25 PPS):**
   - While sporadic peaks of up to 300 kbps were observed, these higher rates could not be reliably
     or stably reproduced.

### Server Invocation

```bash
iperf3 -s
```

### Client Invocation

```bash
iperf3 -c <SERVER_IP> -l 512 -b 128k
```
