FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    iputils-ping \
    dnsutils \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
