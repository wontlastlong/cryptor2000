#include "pch.h"
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <wincrypt.h>
#include <tchar.h>
#include <WinCryptEx.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define BLOCK_LENGTH 4096
#define MAX_PASS_SIZE 1024
#define CONTAINER _TEXT("Rell9e") 

void HandleError(char *s);
void CleanUp(void);

HCRYPTPROV hProv = 0;
HCRYPTHASH hHash = 0;
HCRYPTHASH hSignHash = 0;
HCRYPTKEY hKey = 0;
HCRYPTKEY hPubKey = 0;

BYTE *pbIV = NULL, *pbSig = NULL, *pbKeyBlob;

enum TMODE { TENCRYPT, TDECRYPT };
TMODE mode;

DWORD cbContent, cipher_mode = CRYPT_MODE_CBC;
DWORD dwIV, dwSigLen, dwBlobLen;

BYTE pbContent[BLOCK_LENGTH];
char passphrase[MAX_PASS_SIZE + 1] = "";
char priv_key_pass[MAX_PASS_SIZE + 1] = "";

FILE *fSource = NULL, *fOut = NULL, *fVec = NULL, *fSig = NULL;
FILE *fPubKey = NULL;



void print_usage(char *argv[]) {
	printf(
		"Usage: %s mode in out iv sign pubkey [-f passphrase_file]\n"
		"mode: encrypt/decrypt\n"
		"in: input file\n"
		"out: output file\n"
		"iv: IV file\n"
		"sig: signature file\n"
		"pubkey: public key file\n"
		"Optional:\n"
		"\t-f passphrase_fle: file with passphrase\n",
		argv[0]
	);
}

void encrypt_and_sign(char *argv[]) {
	if (CryptGetKeyParam(
		hKey,
		KP_IV,
		pbIV,
		&dwIV,
		NULL))
	{
		printf("IV of key determined. \n");
	}
	else
	{
		HandleError((char*)"Error getting IV.");
	}

	fVec = fopen(argv[4], "wb");
	printf("iv_file: %s\n", argv[4]);
	fwrite(pbIV, 1, dwIV, fVec);
	fclose(fVec);

	if (CryptGetUserKey(
		hProv,
		AT_SIGNATURE,
		&hPubKey))
	{
		printf("The signature key has been acquired. \n");
	}
	else
	{
		HandleError("Error during CryptGetUserKey for signkey.");
	}

	if (CryptExportKey(
		hPubKey,
		0,
		PUBLICKEYBLOB,
		0,
		NULL,
		&dwBlobLen))
	{
		printf("Size of the BLOB for the public key determined. \n");
	}
	else
	{
		HandleError("Error computing BLOB length.");
	}

	pbKeyBlob = (BYTE*)malloc(dwBlobLen);

	if (CryptExportKey(
		hPubKey,
		0,
		PUBLICKEYBLOB,
		0,
		pbKeyBlob,
		&dwBlobLen))
	{
		printf("Contents have been written to the BLOB. \n");
	}
	else
	{
		HandleError("Error during CryptExportKey.");
	}

	fPubKey = fopen(argv[6], "wb");
	fwrite(pbKeyBlob, 1, dwBlobLen, fPubKey);
	fclose(fPubKey);

	if (CryptCreateHash(
		hProv,
		CALG_GR3411_2012_256,
		0,
		0,
		&hSignHash))
	{
		printf("Hash for signature has been created. \n");
	}
	else
	{
		HandleError((char*)"Error during CryptCreateHash.");
	}


	do
	{
		cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH, fSource);
		if (cbContent)
		{
			BOOL bFinal = feof(fSource);

			if (CryptEncrypt(
				hKey,
				0,
				bFinal,
				0,
				pbContent,
				&cbContent,
				BLOCK_LENGTH))
			{
				printf("Encryption succeeded. \n");
				if (fwrite(
					pbContent,
					1,
					cbContent,
					fOut))
				{
					printf("The encrypted content was written to the '%s'\n", argv[3]);
				}
				else
				{
					HandleError("The encrypted content can not be written\n");
				}
			}
			else
			{
				HandleError("Encryption failed.");
			}

			if (CryptHashData(
				hSignHash,
				pbContent,
				cbContent,
				0))
			{
			}
			else
			{
				HandleError((char*)"Error during CryptHashData.");
			}

			if (bFinal) {
				if (CryptSignHash(
					hSignHash,
					AT_SIGNATURE,
					NULL,
					0,
					NULL,
					&dwSigLen))
				{
				}
				else
				{
					HandleError((char*)"Error during CryptSignHash.");
				}

				pbSig = (BYTE*)malloc(dwSigLen);
				if (CryptSignHash(
					hSignHash,
					AT_SIGNATURE,
					NULL,
					0,
					pbSig,
					&dwSigLen))
				{
				}
				else
				{
					HandleError((char*)"Error during CryptSignHash.");
				}

				fSig = fopen(argv[5], "wb");


				if (fwrite(
					pbSig,
					1,
					dwSigLen,
					fSig))
				{
					printf("The signature was written to the '%s'\n", argv[5]);
				}
				else
				{
					HandleError("The signature can not be written\n");
				}

				fclose(fSig);

				for (int i = 0; i < dwSigLen; ++i) {
					printf("%02x", pbSig[i]);
				}
				printf("\n");
			}
		}
		else
		{
			HandleError("Problem reading the input file\n");
		}
	} while (!feof(fSource));
}

void verify_and_decrypt(char *argv[]) {
	fSig = fopen(argv[5], "rb");
	printf("sig_file: %s\n", argv[5]);

	fseek(fSig, 0, SEEK_END);
	dwSigLen = ftell(fSig);
	fseek(fSig, 0, SEEK_SET);

	pbSig = (BYTE*)malloc(dwSigLen + 1);
	fread(pbSig, 1, dwSigLen, fSig);
	fclose(fSig);

	for (int i = 0; i < dwSigLen; ++i) {
		printf("%02x", pbSig[i]);
	}
	printf("\n");

	fPubKey = fopen(argv[6], "rb");
	printf("pubkey_file: %s\n", argv[6]);

	fseek(fPubKey, 0, SEEK_END);
	dwBlobLen = ftell(fPubKey);
	fseek(fPubKey, 0, SEEK_SET);

	pbKeyBlob = (BYTE*)malloc(dwBlobLen + 1);
	fread(pbKeyBlob, 1, dwBlobLen, fPubKey);
	fclose(fPubKey);

	if (CryptCreateHash(
		hProv,
		CALG_GR3411_2012_256,
		0,
		0,
		&hSignHash))
	{
		printf("Hash for signature has been created. \n");
	}
	else
	{
		HandleError((char*)"Error during CryptCreateHash.");
	}

	do
	{
		cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH, fSource);

		if (CryptHashData(
			hSignHash,
			pbContent,
			cbContent,
			NULL))
		{
		}
		else
		{
			HandleError((char*)"Error during CryptHashData.");
		}

		if (cbContent)
		{
			BOOL bFinal = feof(fSource);
		}
		else
		{
			HandleError("Problem reading the input file\n");
		}
	} while (!feof(fSource));

	if (CryptImportKey(
		hProv,
		pbKeyBlob,
		dwBlobLen,
		0,
		0,
		&hPubKey))
	{
		printf("The signature key has been acquired. \n");
	}
	else
	{
		HandleError("Error during CryptImportKey for signkey.");
	}

	if (CryptVerifySignature(
		hSignHash,
		pbSig,
		dwSigLen,
		hPubKey,
		NULL,
		0))
	{
		printf("The signature has been verified.\n");
	}
	else
	{
		HandleError("Signature not validated!\n");
	}


	fVec = fopen(argv[4], "rb");
	printf("iv_file: %s\n", argv[4]);
	fread(pbIV, 1, dwIV, fVec);
	fclose(fVec);

	if (CryptSetKeyParam(
		hKey,
		KP_IV,
		pbIV,
		NULL))
	{
		printf("IV set. \n");
	}
	else
	{
		HandleError((char*)"Error setting IV.");
	}

	fseek(fSource, 0, SEEK_SET);

	do
	{
		cbContent = (DWORD)fread(pbContent, 1, BLOCK_LENGTH, fSource);
		if (cbContent)
		{
			BOOL bFinal = feof(fSource);
			if (CryptDecrypt(
				hKey,
				0,
				bFinal,
				0,
				pbContent,
				&cbContent))
			{
				printf("Decryption succeeded. \n");
				if (fwrite(
					pbContent,
					1,
					cbContent,
					fOut))
				{
					printf("The decrypted content was written to the '%s'\n", argv[3]);
				}
				else
				{
					HandleError("The decrypted content can not be written\n");
				}
			}
			else
			{
				HandleError("Decryption failed.");
			}
		}
		else
		{
			HandleError("Problem reading the input file\n");
		}
	} while (!feof(fSource));
}


int main(int argc, char *argv[]) {
	if (argc < 7) {
		print_usage(argv);
		return 0;
	}

	if (argc == 7) {
		if (strcmp(argv[1], "encrypt") == 0) {
			mode = TENCRYPT;
		} else if (strcmp(argv[1], "decrypt") == 0) {
			mode = TDECRYPT;
		} else {
			print_usage(argv);
			return 0;
		}

		printf("Enter passphrase: ");
		fgets(passphrase, MAX_PASS_SIZE, stdin);
	} else if (argc == 9) {
		if (strcmp(argv[7], "-f") != 0) {
			print_usage(argv);
			return 0;
		}

		FILE *fPass = fopen(argv[8], "rb");
		fread(passphrase, 1, MAX_PASS_SIZE, fPass);
		fclose(fPass);
	} else {
		print_usage(argv);
		return 0;
	}

	printf("PAss: %s\n", passphrase);

	fSource = fopen(argv[2], "rb");
	if (fSource) {
		printf("ok...?\n");
	}
	printf("in_file: %s\n", argv[2]);
	fOut = fopen(argv[3], "wb");
	printf("out_file: %s\n", argv[3]);

	if (CryptAcquireContext(
		&hProv,
		CONTAINER,
		NULL,
		PROV_GOST_2012_256,
		0))
	{
		printf("Context has been acquired. \n");
	}
	else
	{
		HandleError((char*)"Error during CryptAcquireContext.");
	}


	if (CryptCreateHash(
		hProv,
		CALG_GR3411,
		NULL,
		NULL,
		&hHash))
	{
		printf("Hash has been created. \n");
	}
	else
	{
		HandleError((char*)"Error during CryptCreateHash.");
	}


	if (CryptHashData(
		hHash,
		(BYTE*)passphrase,
		strlen(passphrase),
		NULL))
	{
		printf("Hash algorithm has been fed with data. \n");
	}
	else
	{
		HandleError((char*)"Error during CryptHashData.");
	}


	if (CryptDeriveKey(
		hProv,
		CALG_GR3412_2015_K,
		hHash,
		NULL,
		&hKey))
	{
		printf("Key has been derived. \n");
	}
	else
	{
		HandleError((char*)"Error during CryptDeriveKey.");
	}

	if (CryptGetKeyParam(
		hKey,
		KP_IV,
		NULL,
		&dwIV,
		NULL))
	{
		printf("Size of the IV for the key determined. \n");
	}
	else
	{
		HandleError((char*)"Error computing IV length.");
	}

	if (CryptSetKeyParam(
		hKey,
		KP_MODE,
		(BYTE*)&cipher_mode,
		NULL))
	{
		printf("Cipher mode set. \n");
	}
	else
	{
		HandleError((char*)"Error setting cipher mode.");
	}

	pbIV = (BYTE*)malloc(dwIV);

	if (mode == TENCRYPT) {
		encrypt_and_sign(argv);
	} else if (mode == TDECRYPT) {
		verify_and_decrypt(argv);
	}
}

void CleanUp(void)
{
	if (fSource)
		fclose(fSource);
	if (fOut)
		fclose(fOut);
	if (fVec)
		fclose(fVec);
	if (fSig)
		fclose(fSig);
	if (fPubKey)
		fclose(fPubKey);

	if (hKey)
		CryptDestroyKey(hKey);
	if (hPubKey)
		CryptDestroyKey(hPubKey);

	if (hHash)
		CryptDestroyHash(hHash);
	if (hSignHash)
		CryptDestroyHash(hSignHash);

	if (hProv)
		CryptReleaseContext(hProv, 0);

	if (pbIV)
		free(pbIV);
	if (pbSig)
		free(pbSig);
	if (pbKeyBlob)
		free(pbKeyBlob);

}

void HandleError(char *s)
{
	DWORD err = GetLastError();
	printf("Error number     : 0x%x\n", err);
	printf("Error description: %s\n", s);
	CleanUp();
	if (!err) err = 1;
	exit(err);
}
