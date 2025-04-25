"""Configuration constants for the controller."""

# Priority of the TCP forwarding rules.
TCP_FORWARDING_RULE_PRIORITY = 100
# Threshold for the TCP stream volume: if the volume is greater than this value, a rule will be
# installed to forward the TCP stream directly bypassing the controller. Value is in bytes.
TCP_STREAM_VOLUME_THRESHOLD = 25 * 1000 * 1000  # 25 MB
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
