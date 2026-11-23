FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Bỏ qua kiểm tra thời gian của tệp Release trong APT
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/10no-check-valid-until && \
    echo 'Acquire::Check-Valid-Until::InRelease "false";' >> /etc/apt/apt.conf.d/10no-check-valid-until

RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    libcrypto++-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN g++ -O2 aes_demo.cpp -o aes_demo -lcryptopp
RUN g++ -O2 BlockRunningTime.cpp -o BlockRunningTime 

CMD ["sh", "-c", "./BlockRunningTime && echo '---' && ./aes_demo"]