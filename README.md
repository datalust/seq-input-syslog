# `squiflog`

Ingest [Syslog 5424](https://tools.ietf.org/html/rfc5424) messages via UDP into [Seq](https://datalust.co/seq). The app is packaged both as a plug-in Seq App for all platforms, and as a standalone Docker container that forwards events to Seq via its HTTP API.

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

Important: `squiflog` only supports `--log-opt syslog-format=rfc5424` (and `--log-opt syslog-format=rfc5424micro`, but this is not thoroughly tested). If let unset, the `syslog-format` may default to [Syslog 3164](https://tools.ietf.org/html/rfc3164) (obsolete). [More information on Docker syslog here](https://docs.docker.com/config/containers/logging/syslog/).
