# Running on Zodiac FX Switches

This section details specific considerations and workarounds required when running the project on
**Zodiac FX** switches.

## Project Requirement and Hardware Limitations

Project specifications mandate that all network traffic for a TCP connection must transit through
the control plane via the SDN controller _before_ the connection is promoted to an "elephant flow."

On Zodiac FX hardware, this requirement to route initial TCP traffic through its control plane leads
to significant stability issues, including:

- Sudden reboots of the switch.
- Packet loss occurring even before packets reach the SDN controller. This is particularly evident
  when the control plane path is subjected to sudden bursts of traffic.

These issues appear to be specific to how the Zodiac FX hardware's control plane path handles
sustained or bursty traffic under these conditions.

## Workaround for iPerf3 Measurements

To enable stable `iPerf3` measurements despite the aforementioned hardware limitations, the
following workarounds were found to be necessary:

1.  **Prevent `iPerf3` Send Bursts using `-l 512`:**

    - By default, `iPerf3` can buffer a significant amount of data (e.g., up to its default 128KB
      TCP socket buffer size) and then attempt to send it as rapidly as possible. This behavior
      creates large, sudden bursts of packets.
    - When all initial TCP connection traffic must pass through the Zodiac FX's control plane, these
      high-rate bursts can overwhelm its processing capacity or input queues, leading to the
      observed instability and packet loss.
    - The `iPerf3` client option `-l 512` (set read/write buffer length to 512 Bytes) instructs
      `iPerf3` to perform application-level reads/writes in smaller 512-byte chunks. This means
      `iPerf3` feeds data to the underlying TCP socket more gradually.
    - This more measured data submission from the application helps the TCP stack to pace packets
      more smoothly, preventing the formation of large, high-rate bursts. This allows the traffic to
      stay within the handling capacity of the switch's control plane path.
    - **Crucially, the primary purpose of using `-l 512` in this context is to manage the traffic
      flow from `iPerf3` to prevent these overwhelming bursts, not because of an inherent issue with
      individual packets of a certain size (e.g., MSS limitations).**

2.  **Limit Average Bandwidth to 128 kbps using `-b 128k`:**
    - This `iPerf3` client option sets the target average bitrate to 128 kilobits per second.
    - When combined with the burst prevention technique provided by `-l 512`, this average rate was
      found to be sustainable for the Zodiac FX control plane path.
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
