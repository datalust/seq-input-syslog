# squiflog
Ingest syslog payloads into Seq


# Example with docker

```
docker run \
    --log-driver syslog \
    --log-opt syslog-address=udp://<your-docker-ip>:5000 \
    --log-opt syslog-format=rfc5424 \
      alpine echo hello world
``` 
