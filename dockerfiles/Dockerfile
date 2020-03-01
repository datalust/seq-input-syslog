FROM datalust/seqcli:latest

COPY target/x86_64-unknown-linux-musl/release/squiflog /bin/squiflog
COPY dockerfiles/run.sh /run.sh

EXPOSE 12201

ENV SEQ_ADDRESS=http://localhost:5341
ENV SEQ_API_KEY=
ENV SYSLOG_ADDRESS=

ENTRYPOINT ["/run.sh"]
