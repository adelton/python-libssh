
NAME = python-$(shell eval echo $$( awk '/^name/ { print $$NF }' pyproject.toml))
VERSION = $(shell eval echo $$( awk '/^version/ { print $$NF }' pyproject.toml))
DIST = dist
SPECFILE = $(NAME).spec

tar-gz:
	rm -rf $(DIST)/$(NAME)-$(VERSION)
	mkdir -p $(DIST)/$(NAME)-$(VERSION)
	cp -rp -t dist/$(NAME)-$(VERSION) $(shell ls | grep -v dist)
	for i in $(shell cat .gitignore) ; do rm -rf $(DIST)/$$i ; done
	tar -C $(DIST) -cvzf $(DIST)/$(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf $(DIST)/$(NAME)-$(VERSION)
	ls -l $(DIST)/*.tar.gz

srpm: tar-gz
	rpmbuild -D '_srcrpmdir $(DIST)' -D '_sourcedir $(DIST)' -bs $(SPECFILE)
	ls -l $(DIST)/*.src.rpm

dynamic-build-requires: tar-gz
	rpmbuild -D '_srcrpmdir $(DIST)' -D '_sourcedir $(PWD)/$(DIST)' -br $(SPECFILE)

rpm: tar-gz
	rpmbuild -D '_rpmdir $(DIST)' -D '_sourcedir $(PWD)/$(DIST)' -bb $(SPECFILE)
	mv $(DIST)/$$(uname -m)/*.$$(uname -m).rpm $(DIST)
	ls -l $(DIST)/*.$$(uname -m).rpm
	# rpm -qlp $(DIST)/*.$$(uname -m).rpm
	# rpm -q --requires -p $(DIST)/*.$$(uname -m).rpm

test:
	./test.sh

test-pylint:
	pylint-3 --disable=R --disable=C --indent-string="\t" --extension-pkg-whitelist=rpm,lxml libssh.pyx

clean:
	rm -rf $(shell cat .gitignore)

.PHONY: tar-gz srpm rpm test test-pylint clean

