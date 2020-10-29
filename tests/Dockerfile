FROM registry.fedoraproject.org/fedora
RUN dnf install -y --setopt=install_weak_deps=False python3-devel python3-Cython make gcc libssh-devel openssh-server openssh-clients rpm-build
RUN for i in rsa ecdsa ed25519 ; do /usr/libexec/openssh/sshd-keygen $i ; done
RUN mkdir ~/.ssh && echo localhost $( cat /etc/ssh/ssh_host_ecdsa_key.pub ) > ~/.ssh/known_hosts
RUN yes | ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
RUN cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys && chmod 400 ~/.ssh/authorized_keys
COPY . /src/
WORKDIR /src
RUN python3 setup.py build_ext --inplace
RUN python3 setup.py bdist_rpm
RUN rpm -Uvh dist/python-libssh*.x86_64.rpm
ENTRYPOINT [ "/usr/sbin/sshd", "-D" ]
