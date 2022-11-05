FROM registry.fedoraproject.org/fedora
RUN if test -f /etc/centos-release ; then dnf install -y 'dnf-command(config-manager)' ; fi
RUN if test -f /etc/centos-release && grep 'CentOS Stream release 8' /etc/centos-release ; then \
	dnf config-manager --set-enabled powertools ; fi
RUN if test -f /etc/centos-release && grep 'CentOS Stream release 9' /etc/centos-release ; then \
	dnf config-manager --set-enabled crb ; fi
RUN dnf install -y --setopt=install_weak_deps=False python3-devel python3-setuptools python3-Cython make gcc libssh-devel openssh-server openssh-clients rpm-build
RUN if test -f /etc/nsswitch.conf ; then grep hosts: /etc/nsswitch.conf && sed -i 's/^hosts:.*/hosts: files dns myhostname/' /etc/nsswitch.conf ; fi
RUN echo 'set enable-bracketed-paste off' >> ~root/.inputrc
RUN for i in rsa ecdsa ed25519 ; do /usr/libexec/openssh/sshd-keygen $i ; done
RUN mkdir -p ~/.ssh && echo localhost $( cat /etc/ssh/ssh_host_ecdsa_key.pub ) > ~/.ssh/known_hosts
RUN yes | ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
RUN cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys && chmod 400 ~/.ssh/authorized_keys
COPY . /src/
WORKDIR /src
RUN python3 setup.py build_ext --inplace
RUN python3 setup.py bdist_rpm
RUN rpm -Uvh dist/python-libssh*.rpm
ENTRYPOINT [ "/usr/sbin/sshd", "-D" ]
