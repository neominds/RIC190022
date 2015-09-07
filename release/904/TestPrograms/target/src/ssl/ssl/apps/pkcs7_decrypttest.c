/*
 * Copyright (c) 2015 WRKK / WRS, Jayesh Babu
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define RSA_SERVER_CERT "server3.crt"
#define RSA_SERVER_KEY  "server3.key"

/*
   EnvelopedData ::= SEQUENCE {
     version Version,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo }

   RecipientInfos ::= SET OF RecipientInfo

   EncryptedContentInfo ::= SEQUENCE {
     contentType ContentType,
     contentEncryptionAlgorithm
       ContentEncryptionAlgorithmIdentifier,
     encryptedContent
       [0] IMPLICIT EncryptedContent OPTIONAL }

   EncryptedContent ::= OCTET STRING

*/


int cve_1790app(char *filename)
{
	int encrypt,flags_nm=0,out_size=0;
	PKCS7 *pkcs7;
	const EVP_CIPHER *cipher;
	X509 *cert;
	EVP_PKEY *pkey;
	FILE *fp;
	BIO *pkcs7_bio,*out,*in_fileBIO;
	int i=0;
	
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
		

	if (!(out = BIO_new_fp(stdout, BIO_NOCLOSE)))
	{
		fprintf(stderr, "Error creating output BIO objects\n");
		goto err;
	}
	
	// read from file and Decrypt 
	{
		if (!(fp = fopen(RSA_SERVER_KEY, "r")) ||!(pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)))
		{
			printf("Error reading private key in %s\n",RSA_SERVER_KEY);
			goto err;
		}
		fclose(fp);
		
		if (!(fp = fopen(RSA_SERVER_CERT, "r")) ||!(cert = PEM_read_X509(fp, NULL, NULL, NULL)))
		{
			printf( "Error reading decryption certificate in %s\n",	RSA_SERVER_CERT);
			goto err;
		}
		fclose(fp);
		
		//create a file BIO for input file
		in_fileBIO = BIO_new_file(filename,"r");
		if( in_fileBIO == NULL){ 
			printf("Error in creating bio file\n"); 
			goto err;
		}		
		
		if (!(pkcs7 = SMIME_read_PKCS7(in_fileBIO, &pkcs7_bio)))
		{
			printf("\nError reading PKCS#7 object\n");
			goto err;
		}
		
		printf("Invoking PKCS7_decrypt function..\n");
		if (PKCS7_decrypt(pkcs7, pkey, cert, out, flags_nm) != 1)
		{
			printf("Error decrypting PKCS#7 object\n");
			goto err;
		}
	}

	BIO_free(in_fileBIO);

	return 0;
err:
	return -1;
}