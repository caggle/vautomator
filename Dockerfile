FROM ruby:latest
MAINTAINER Jonathan Claudius

# Make a landing location for results
RUN mkdir -p /app/results

# Update deps and install make utils for compiling tools
RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y make && \
    apt-get install -y curl

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
RUN echo 'deb http://download.opensuse.org/repositories/home:/cabelo/Debian_9.0/ /' > /etc/apt/sources.list.d/home:cabelo.list
RUN apt-get update
RUN apt-get install owasp-zap

# Install HTTP Observatory tool
RUN apk --update add nodejs && \
    rm -rf /var/cache/apk/* && \
    npm install -g observatory-cli

# Install TLS Observatory tool
# First build latest Go from master
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

WORKDIR $GOPATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH" && \
    git clone https://github.com/golang/go.git /tmp/go && \
	cd /tmp/go/src && \
	./make.bash && \
	rm -rf /usr/local/go; \
	mv /tmp/go /usr/local/; \
	rm -rf /usr/local/go/.git*; \
	rm -rf /tmp/*; \
	go version && \

# We have a working go installation, get tlsobs binary
ENV GOPATH $HOME/go
RUN mkdir $GOPATH
ENV PATH $GOPATH/bin:$PATH
RUN go get github.com/mozilla/tls-observatory/tlsobs

# Copy over relevant files we need
RUN pip3 install -r ./requirements.txt
COPY ./run.py /app/run.py
RUN chmod -x /app/run.py