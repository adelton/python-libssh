FROM registry.fedoraproject.org/fedora
RUN dnf install -y --setopt=install_weak_deps=False python3-devel python3-Cython gcc libssh-devel
COPY . /src/
WORKDIR /src
RUN python3 setup.py build_ext --inplace
RUN python3 setup.py test
