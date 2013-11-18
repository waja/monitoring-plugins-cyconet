#!/bin/sh
set -e

PKGNAME="monitoring-plugins-cyconet"
FILES="debian/control.in debian/rules debian/README.source debian/README.Debian.plugins.in debian/packaging-helper.py"
TDIR="$(mktemp -d -t ${PKGNAME}.XXXXXX)"
trap '[ ! -d "${TDIR}" ] || rm -rf "${TDIR}"' EXIT

git clone https://github.com/bzed/pkg-nagios-plugins-contrib.git "${TDIR}"/pkg-nagios-plugins-contrib
for FILE in ${FILES}; do
	if [ "${FILE}" = "debian/README.source" ]; then
		sed -i "s/pkg-nagios-plugins-contrib/${PKGNAME}/g" ${TDIR}/pkg-nagios-plugins-contrib/${FILE}
	fi
	if [ "${FILE}" = "debian/control.in" ]; then
		sed -i "s#^Vcs-Git:.*#Vcs-Git: git://github.com/waja/blah#" ${TDIR}/pkg-nagios-plugins-contrib/${FILE}
		sed -i "s#^Vcs-Browser:.*#Vcs-Browser: http://github.com/waja/blah#" ${TDIR}/pkg-nagios-plugins-contrib/${FILE}
	fi
	sed -i "s/nagios-plugins-contrib/${PKGNAME}/g" ${TDIR}/pkg-nagios-plugins-contrib/${FILE}
	cp ${TDIR}/pkg-nagios-plugins-contrib/${FILE} ./${FILE}
done
