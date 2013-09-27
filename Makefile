
PROG=	gss-token
SRCS=	gss-token.c base64.c

LDADD+=	-lgssapi

NOMAN=1
WARNS=4

.include <bsd.prog.mk>
