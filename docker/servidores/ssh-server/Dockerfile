FROM ubuntu:24.04
RUN apt update
RUN apt install openssh-server rsyslog ptunnel-ng -y
RUN ssh-keygen -A && \
    echo 'root:0cGSCgtThAm3bDng8LjIm7t2' | chpasswd && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'LogLevel VERBOSE' >> /etc/ssh/sshd_config
COPY servidores/ssh-server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]