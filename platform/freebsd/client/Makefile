
PORTNAME=	netidm
# DISTVERSION=    1.5.0-dev
# DISTVERSIONPREFIX=	v

DISTVERSION=    g20250102
GH_TAGNAME=     edb8cccc84e9dacd2ac31ea1162dd24c0c454c55
GH_ACCOUNT=     Firstyear

CATEGORIES=	security net databases

LICENSE=        MPL20
LICENSE_FILE=   ${WRKSRC}/LICENSE.md
MAINTAINER=	william@blackhats.net.au
COMMENT=	Simple and secure identity management platform
WWW=		https://github.com/netidm/netidm/

USES=		cargo ssl
USE_GITHUB=	yes

ONLY_FOR_ARCHS=	aarch64 amd64

CARGO_ENV=      NETIDM_BUILD_PROFILE=release_freebsd

CARGO_BUILD_ARGS = -p netidm_tools -p netidm_unix_int -p nss_netidm -p pam_netidm

CARGO_INSTALL=  no

USE_RC_SUBR=	netidm_unixd netidm_unixd_tasks

USERS=  _netidm_unixd
GROUPS= _netidm_unixd

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/netidm ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/netidm-unix ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/netidm_ssh_authorizedkeys ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/netidm_ssh_authorizedkeys_direct ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/netidm_unixd ${STAGEDIR}${PREFIX}/libexec
	${INSTALL_PROGRAM} ${WRKDIR}/target/release/netidm_unixd_tasks ${STAGEDIR}${PREFIX}/libexec
	${INSTALL_LIB} ${WRKDIR}/target/release/libnss_netidm.so ${STAGEDIR}${PREFIX}/lib/nss_netidm.so.1
	${INSTALL_LIB} ${WRKDIR}/target/release/libpam_netidm.so ${STAGEDIR}${PREFIX}/lib
	${MKDIR} ${STAGEDIR}${PREFIX}/etc
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/netidm
	${MKDIR} ${STAGEDIR}/var/run/netidm-unixd
	${MKDIR} ${STAGEDIR}/var/lib/netidm-unixd
	${MKDIR} ${STAGEDIR}/var/cache/netidm-unixd

.include <bsd.port.mk>
