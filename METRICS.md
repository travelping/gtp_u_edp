gtp_u_edp metrics
=================

gtp_u_edp uses exometer core to implement various operation metrics.

The following metrics exist:

| Metric                                                               | Type      |
| -------------------------------------------------------------------- | --------- |
| socket.gtp-u.\<SocketName\>.rx.v1.\<GTPv1-U-MessageName\>            | counter   |
| socket.gtp-u.\<SocketName\>.pt.v1.\<GTPv1-U-MessageName\>            | histogram |
| socket.gtp-u.\<SocketName\>.\<Error\>.pt                             | histogram |
| socket.gtp-u.\<SocketName\>.\<Error\>.count                          | counter   |

\<SocketName\> is taken from the configuration.

The `rx` metrics count the number of message of a given type received. The `pt`
metrics are a histogram of the total processing time for the last incoming
message of that type.

All timing values in the histograms are in microseconds (µs).

Counters for the following GTPv1-U Messages types exist:

 * echo\_request
 * error\_indication
 * version\_not\_supported
 * end\_marker
 * g\_pdu

Counter for the following errors exist:

 * context\_not\_found
 * invalid\_payload
 * send\_failed
