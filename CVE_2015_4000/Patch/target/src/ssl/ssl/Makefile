# Makefile - makefile for ../ssl
#
# modification history
# --------------------
# 01b, 05nov04,tat     added -DOPENSSL_NO_CAST
# 01a, 18mar04,cdw     written
#
# DESCRIPTION
# This file contains the makefile rules for building OpenSSL in the
# Tornado framework 
#*/

TGT_DIR=$(WIND_BASE)/target
USR_BUILD=no


ifeq ($(SPACE),user)
    USR_BUILD=yes
endif

ifeq ($(SPACE),USER)
    USR_BUILD=yes
endif


ifeq ($(USR_BUILD),yes)
    TGT_DIR =$(WIND_USR)
    MAKE_INCLUDE_PATH=$(WIND_USR)
else     
    TGT_DIR =$(WIND_BASE)/target
    MAKE_INCLUDE_PATH=$(TGT_DIR)/h
endif 




BF_ENC =	bf_enc.o
BN_ASM =	bn_asm.o
CAST_ENC =	c_enc.o
COMPATOBJ =	ui_compat.o
DES_ENC =	des_enc.o fcrypt_b.o
MD5_ASM_OBJ =
RC4_ENC =	rc4_enc.o
RC5_ENC =	rc5_enc.o
RMD160_ASM_OBJ =
SHA1_ASM_OBJ =

BNTEST =	bntest
ECTEST =	ectest
EXPTEST =	exptest
IDEATEST =	ideatest
SHATEST =	shatest
SHA1TEST =	sha1test
MDC2TEST =	mdc2test
RMDTEST =	rmdtest
MD2TEST =	md2test
MD4TEST =	md4test
MD5TEST =	md5test
HMACTEST =	hmactest
RC2TEST =	rc2test
RC4TEST =	rc4test
RC5TEST =	rc5test
BFTEST =	bftest
CASTTEST =	casttest
DESTEST =	destest
RANDTEST =	randtest
DHTEST =	dhtest
DSATEST =	dsatest
METHTEST =	methtest
SSLTEST =	ssltest
RSATEST =	rsa_test
ENGINETEST =	enginetest
EVPTEST =	evp_test

LIB_BASE_NAME=openssl

override EXTRA_DEFINE+=-DOPENSSLDIR="\"./\"" -DOPENSSL_SYSNAME_VXWORKS \
	-DOPENSSL_NO_KRB5 -DOPENSSL_NO_HW -DOPENSSL_NO_CAST -DOPENSSL_NO_CAST5\
	-DOPENSSL_NO_ASM -DOPENSSL_NO_MDC2 -DOPENSSL_NO_IDEA \
	-DOPENSSL_NO_ENGINE -DOPENSSL_NO_RC5 -DOPENSSL_NO_RC2 \
        -DOPENSSL_NO_BF -DOPENSSL_NO_SPEED -DNO_STRINGS_H \
        -DOPENSSL_NO_DESX -DOPENSSL_NO_EC -DRIC_190022 \
	 $(DEBUG_FLAG) -I$(TGT_DIR)/h/openssl \
	-I. -I.. -I../.. -I$(TGT_DIR)/src/security/utilities/misc \
	-I$(TGT_DIR)/h/openssl/private 

SUBDIRS = apps

OBJS = 	\
	s2_meth.o  s2_srvr.o  s2_clnt.o  s2_lib.o  s2_enc.o s2_pkt.o \
	s3_meth.o  s3_srvr.o  s3_clnt.o  s3_lib.o  s3_enc.o s3_pkt.o s3_both.o \
	s23_meth.o s23_srvr.o s23_clnt.o s23_lib.o          s23_pkt.o \
	t1_meth.o   t1_srvr.o t1_clnt.o  t1_lib.o  t1_enc.o \
	ssl_lib.o ssl_err2.o ssl_cert.o ssl_sess.o \
	ssl_ciph.o ssl_stat.o ssl_rsa.o \
	ssl_asn1.o ssl_txt.o ssl_algs.o \
	bio_ssl.o ssl_err.o kssl.o

OBJS+= ssl_link_syms.o

#include $(TGT_DIR)/h/make/rules.library
include $(MAKE_INCLUDE_PATH)/make/rules.library

