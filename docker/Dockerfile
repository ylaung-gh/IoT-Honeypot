# Getting ubuntu base image
FROM ubuntu:20.04

MAINTAINER SUTD iTrust ReSILIoT

SHELL ["/bin/bash", "-c"]

# Install the necessary tools & create TUN/TAP device
RUN apt update && \
    apt upgrade -y && \
    apt install -y \
        iputils-ping \
        traceroute \
        net-tools \
        openvpn \
        socat \
        tshark \
        nano

# Copy the OpenVPN config and post initialization script
COPY ovpn-config /root/ovpn-config
COPY container-scripts /root
