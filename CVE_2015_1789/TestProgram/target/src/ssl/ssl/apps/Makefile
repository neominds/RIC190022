# Makefile - makefile for apps
#
# modification history
# --------------------
# 01b, 13Jan04,cdw              updates for OpenSSL 0.9.7e
# 01a, 18mar04,cdw    		written
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
	-DOPENSSL_NO_KRB5 -DOPENSSL_NO_HW -DOPENSSL_NO_CAST \
	-DOPENSSL_NO_ASM -DOPENSSL_NO_MDC2 -DOPENSSL_NO_IDEA \
	-DOPENSSL_NO_ENGINE -DOPENSSL_NO_RC5 -DOPENSSL_NO_RC2 \
        -DOPENSSL_NO_BF -DOPENSSL_NO_SPEED -DNO_STRINGS_H \
	$(DEBUG_FLAG) -I$(TGT_DIR)/h/openssl \
	-I. -I.. -I../.. -I$(TGT_DIR)/src/security/utilities/misc \
	-I$(TGT_DIR)/h/openssl/private -DMONOLITH 

SUBDIRS = 

OBJS= 	openssl.o verify.o asn1pars.o req.o dgst.o dh.o dhparam.o enc.o        \
	passwd.o gendh.o errstr.o ca.o pkcs7.o crl2p7.o crl.o rsa.o rsautl.o   \
	dsa.o dsaparam.o x509.o genrsa.o gendsa.o s_server.o s_client.o	       \
	speed.o s_time.o apps.o s_cb.o s_socket.o app_rand.o version.o	       \
	sess_id.o ciphers.o nseq.o pkcs12.o pkcs8.o spkac.o smime.o rand_app.o \
	engine.o ocsp.o prime.o CVE20151789Server.o

OBJS+= ssl_apps_link_syms.o

#include $(TGT_DIR)/h/make/rules.library
include $(MAKE_INCLUDE_PATH)/make/rules.library

