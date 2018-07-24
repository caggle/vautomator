FROM ruby:latest
MAINTAINER Jonathan Claudius

# Make a landing location for results
RUN mkdir -p /app/results

# Update deps and install make utils for compiling tools
RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y make

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

# Copy over relevant files we need
COPY ./run.py /app/run.py
RUN chmod -x /app/run.py

# Install and compile X


# Install and compile Y


# Install and compile Z