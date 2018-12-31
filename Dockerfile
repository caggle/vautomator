FROM ruby:latest
MAINTAINER Cag

# Make a landing location for results
RUN mkdir -p /app/results && \
    mkdir -p /app/vendor

# Update deps and install make utils for compiling tools
RUN apt-get update && \
    apt-get install -y unzip && \
    apt-get install -y dos2unix && \
    apt-get install -y build-essential && \
    apt-get install -y make && \
    apt-get install -y curl && \
    apt-get install -y python3-pip && \
    apt-get install -y --fix-missing openjdk-8-jdk

RUN cd /app/vendor && \ 
    wget -nv https://bootstrap.pypa.io/get-pip.py && \
    python2 get-pip.py

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

# Install ZAP, and files necessary for ZAP baseline scan
# Installing the deb file may not be needed
# TODO: ZAP still does not work, needs more work on it
# We probably don't need this installed
# RUN cd /tmp && \
#    wget -nv 'https://download.opensuse.org/repositories/home:/cabelo/Debian_9.0/amd64/owasp-zap_2.7.0_amd64.deb' && \
#    dpkg -i /tmp/owasp-zap_2.7.0_amd64.deb && \
#    cd /

RUN gem install zapr
RUN pip2 install --upgrade pip zapcli python-owasp-zap-v2.4

ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/
ENV PATH $JAVA_HOME/bin:/zap/:$PATH
ENV ZAP_PATH /zap/zap.sh
# Default port for use with zapcli
ENV ZAP_PORT 8080
ENV HOME /home/zap/

RUN cd /app/vendor && \
    git clone https://github.com/zaproxy/zaproxy.git

RUN mkdir -p /zap && mkdir -p /home/zap/.ZAP_D/policies/
RUN cp /app/vendor/zaproxy/docker/zap* /zap/
RUN cp -r /app/vendor/zaproxy/docker/policies /home/zap/.ZAP_D/policies/

# Install HTTP Observatory tool
RUN apt-get install -y software-properties-common
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash -
RUN apt-get install -y nodejs && \
    npm install -g observatory-cli

# Install TLS Observatory tool
# First build latest Go from master
RUN cd /tmp && \
    wget -nv https://dl.google.com/go/go1.11.2.linux-amd64.tar.gz && \
    tar -C /app/vendor/ -xzf /tmp/go1.11.2.linux-amd64.tar.gz && \
    cd /

ENV GOPATH /app/vendor/go/bin
ENV PATH $GOPATH:$PATH
ENV PATH $GOPATH/bin:$PATH

RUN go get github.com/mozilla/tls-observatory/tlsobs
RUN wget -nv http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip && \
    wget -nv http://s3.amazonaws.com/alexa-static/top-1m.csv.zip -O alexa-top-1m.csv.zip && \
    mkdir -p /etc/tls-observatory && \
    unzip top-1m.csv.zip && \
    mv top-1m.csv /etc/tls-observatory/cisco-top-1m.csv && \
    unzip alexa-top-1m.csv.zip && \
    mv top-1m.csv /etc/tls-observatory/alexa-top-1m.csv && \
    rm top-1m.csv.zip && rm alexa-top-1m.csv.zip && \
    dos2unix /etc/tls-observatory/cisco-top-1m.csv && dos2unix /etc/tls-observatory/alexa-top-1m.csv

RUN cd /app && \
    git clone https://github.com/caggle/vautomator.git -b dockerized_example
RUN pip3 install -r /app/vautomator/requirements.txt
RUN chmod +x /app/vautomator/run.py
