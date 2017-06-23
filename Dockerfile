FROM alpine
MAINTAINER Tim Thomas

ENV INSTALL_PATH /app
ENV HTTP_PROXY ${http_proxy}
ENV HTTPS_PROXY ${http_proxy}
ENV CFLAGS "-I /usr/include/libxml2"

RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH

COPY . ./

RUN apk add --no-cache py-pip openssl-dev libxslt && \
    apk add --no-cache --virtual .build-deps build-base python2-dev libxml2-dev libxslt-dev libffi-dev && \
    pip install -r requirements.txt && \
    pip install ydkGen/python/ciscolive_ansible_ospf-bundle/dist/ydk-models-ciscolive-ansible-ospf-0.0.1.tar.gz && \
    pip install ydkGen/python/ciscolive_ansible_macsec-bundle/dist/ydk-models-ciscolive-ansible-macsec-0.0.1.tar.gz && \
    apk del .build-deps && \
    apk add --no-cache bash openssh-client sshpass sudo tree && \
    adduser -h $INSTALL_PATH -s /bin/bash -D -H -u 1000 -G users devnet && \
    echo "devnet ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/devnet && \
    chmod 0440 /etc/sudoers.d/devnet && \
    chown -R devnet:users $INSTALL_PATH

CMD ["su", "-", "devnet", "-c", "/bin/bash"]