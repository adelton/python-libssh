FROM registry.fedoraproject.org/fedora
RUN dnf install -y --setopt=install_weak_deps=False python3-devel python3-Cython gcc libssh-devel openssh-server
RUN for i in rsa ecdsa ed25519 ; do /usr/libexec/openssh/sshd-keygen $i ; done
COPY . /src/
WORKDIR /src
RUN python3 setup.py build_ext --inplace
ENTRYPOINT [ "/usr/sbin/sshd", "-D" ]
