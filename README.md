# nginx log exporter

The nginx log exporter allows exporting requests stats
from nginx JSON logs to Prometheus.

## Building and running

### Local Build

    make
    ./nginxlog_exporter <flags>

### Building with Docker

    docker build -t nginxlog_exporter .
    docker run -d -p 9117:9117 --name nginxlog_exporter -v /var/log/nginx:/var/log/nginx:ro nginxlog_exporter -file.pattern "/var/log/nginx/*.log"

