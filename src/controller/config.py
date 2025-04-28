"""Configuration constants for the controller."""

# Priority of the TCP forwarding rules.
TCP_FORWARDING_RULE_PRIORITY = 100
# Threshold for the TCP stream volume: if the volume is greater than this value, a rule will be
# installed to forward the TCP stream directly bypassing the controller. Value is in bytes.
TCP_STREAM_VOLUME_THRESHOLD = 25 * 1000 * 1000  # 25 MB
# Whether to enable the automatic connection cleanup mechanism. If set to True, the controller will
# automatically remove TCP connections that are not active for a certain amount of time. The
# controller will remove the connection from its own internal state; the switches themselves have
# their own timeout mechanism that - if this option is enabled - will be used for the same purpose.
TCP_TIMEOUT_TRACKING = True
# Timeout for the TCP forwarding rules: if the connection is not used for this amount of time, it
# will be removed from the switch or from the controller. Value is in seconds.
TCP_CONNECTION_TIMEOUT = 20

# Log level re-mapping: allows to remap the log levels to different values. This is userful since
# Ryu does not support different log levels for different applications causing our logs to be
# spammed by third-party SDN applications. This is a workaround.
LOG_LEVEL_REMAP = {
    "debug": "info",
    "info": "warning",
    "warning": "error",
}

# Whether to use the topology caching mechanism. If set to True, the controller will cache the
# topology information locally and will not query Ryu for it every time. This improves performance,
# stability against Ryu flaps but as implemented prevents any sort of fault tolerance.
TOPOLOGY_CACHING = True
