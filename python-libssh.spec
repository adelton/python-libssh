
Name:		python-libssh
Version:	0.0.1
Release:	1%{?dist}

Summary:	Python bindings to client functionality of libssh
License:	LGPLv2
URL:		https://github.com/adelton/python-libssh
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	libssh-devel
BuildRequires:	python3-devel
BuildRequires:	python3-wheel

%description
Python bindings to client functionality of libssh.

%prep
%autosetup

%generate_buildrequires
%pyproject_buildrequires -p

%build
%pyproject_wheel

%install
%pyproject_install

%pyproject_save_files -l libssh

%files -f %{pyproject_files}

