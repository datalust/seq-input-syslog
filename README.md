# `squiflog`

Ingest Syslog [RFC 5424](https://tools.ietf.org/html/rfc5424) and [RFC 3164](https://tools.ietf.org/html/rfc3164) messages via UDP into [Seq](https://datalust.co/seq). The app is packaged both as a plug-in [Seq App for all platforms](https://nuget.org/packages/seq.input.syslog), and as a standalone Docker container that forwards events to Seq via its HTTP API.

### Collecting Docker container logs

The output from any Docker container can be collected by configuring its logging driver on startup:

```shell
$ docker run \
    --rm \
    -it \
    --log-driver syslog \
    --log-opt syslog-address=udp://squiflog.example.com:514 \
    --log-opt syslog-format=rfc5424 \
    my-app:latest
```
In this case the `syslog-address` option needs to resolve to the running `squiflog` container.

Note, providing the `--log-opt syslog-format=rfc5424` enables the stricter and more informative RFC 5424 Syslog format. Leaving this unset may default to the earlier RFC 3164 format.
