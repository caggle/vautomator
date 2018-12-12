FROM ruby:latest
MAINTAINER Jonathan Claudius

# Make a landing location for results
RUN mkdir -p /app/results

# Update deps and install make utils for compiling tools
RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y make && \
    apt-get install -y curl && \
    apt-get install -y python3-pip

# Install NMAP
RUN apt-get install -y nmap

# Install and compile dirb
COPY ./vendor/dirb222.tar.gz /app/vendor/dirb222.tar.gz
RUN tar -xvf /app/vendor/dirb222.tar.gz -C /app/vendor/
RUN chmod -R 777 /app/vendor/dirb222
RUN chown -R root /app/vendor/dirb222
RUN cd /app/vendor/dirb222/ && \
    ./configure && \
    make && \
    cd /

# Install ssh_scan
RUN gem install ssh_scan

# Install ZAP
RUN cd /tmp && \
    wget 'https://download.opensuse.org/repositories/home:/cabelo/Debian_9.0/amd64/owasp-zap_2.7.0_amd64.deb' && \
    dpkg -i /tmp/owasp-zap_2.7.0_amd64.deb && \
    cd /

# Install HTTP Observatory tool
RUN apt-get install -y software-properties-common
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN apt-get install -y nodejs && \
    npm install -g observatory-cli

# Install TLS Observatory tool
# First build latest Go from master
RUN cd /tmp && \
    wget https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz && \
    tar -C /app/vendor/ -xzf /tmp/go1.11.2.linux-amd64.tar.gz && \
    cd /

ENV GOPATH /app/vendor/go/bin
ENV PATH $GOPATH:$PATH

RUN go get github.com/mozilla/tls-observatory/tlsobs

# Copy over relevant files we need
# COPY ./run.py /app/run.py
# RUN chmod -x /app/run.py