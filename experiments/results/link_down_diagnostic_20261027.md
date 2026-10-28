# Mininet Link-Down Diagnostic - 2026-10-27

## Result

The diagnostic used the isolated three-switch Mininet triangle and the existing Ryu controller on 127.0.0.1:6653.

- Baseline pingAll: 0.0% packet loss.
- Failure injection: Mininet.configLinkStatus("s1", "s2", "down").
- Linux interface state: both veth endpoints showed DOWN/M-DOWN.
- OpenFlow port description after two seconds: the affected trunk ports still reported state LIVE with config: NO_PACKET_IN.
- Post-injection pingAll: 100.0% packet loss.
- After restoring the link: pingAll returned to 0.0% packet loss.

## Interpretation

The Mininet administrative/interface-down injection did not yield the OpenFlow LINK_DOWN state that Ryu STP uses to trigger port-down handling. The alternate path therefore was not shown to reconverge in this diagnostic.

This is a diagnostic finding, not a successful failover result and not a physical cable-unplug test. Automatic active-link failover remains unresolved. Do not bypass safety restrictions to remove live OVS ports; use an explicitly isolated, approved failure-injection method before claiming cable-failure behavior.
