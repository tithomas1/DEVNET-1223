FROM alpine
MAINTAINER Joel Roberts

ENV INSTALL_PATH /app
ENV HTTP_PROXY ${http_proxy}
ENV HTTPS_PROXY ${http_proxy}
ENV CFLAGS "-I /usr/include/libxml2"

RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH

COPY . ./

RUN apk add --no-cache py-pip openssl-dev libxslt && \
    apk add --no-cache --virtual .build-deps build-base python2-dev python3-dev libxml2-dev libxslt-dev libffi-dev && \
    apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --upgrade pip setuptools && \
    pip install -r requirements.txt && \
    apk del .build-deps && \
    apk add --no-cache bash openssh-client sshpass sudo tree which && \
    rm -r /root/.cache && \
    adduser -h $INSTALL_PATH -s /bin/bash -D -H -u 1000 -G users devnet && \
    echo "devnet ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/devnet && \
    chmod 0440 /etc/sudoers.d/devnet && \
    chown -R devnet:users $INSTALL_PATH

CMD ["su", "-", "devnet", "-c", "/bin/bash"]
