"""Configuration constants for the controller."""

# Priority of the TCP forwarding rules.
TCP_FORWARDING_RULE_PRIORITY = 100
# Threshold for the TCP stream volume: if the volume is greater than this value, a rule will be
# installed to forward the TCP stream directly bypassing the controller. Value is in bytes.
TCP_STREAM_VOLUME_THRESHOLD = 25 * 1000 * 1000  # 25 MB
# Timeout for the TCP forwarding rules: if the connection is not used for this amount of time, it
# will be removed from the switch or from the controller. Value is in seconds.
TCP_CONNECTION_TIMEOUT = 20
