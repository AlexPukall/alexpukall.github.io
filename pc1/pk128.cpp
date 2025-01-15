// file: pk128.cpp
// date: 4/8/2005
// programmer: huey jiang    huey_jiang@hotmail.com
// this version was made basing on Alex Pukall's C version
// and tested on VC++ 6.0
// PC1 in 128-bits
#include <iostream.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>

class PukallCipher
{
	public:

		unsigned short pkax,pkbx,pkcx,pkdx,pksi,pktmp,x1a2;
		unsigned short pkres,pki,inter,cfc,cfd,compte;
		unsigned short x1a0[8];
		unsigned char cle[17];
		short pkc, plainlen, ascipherlen;

		char *plainText, *ascCipherText;

		void pkfin(void);
		void pkcode(void);
		void pkassemble(void);

		void ascii_encrypt128(char *in, char *key);
		void ascii_decrypt128(char *in, char *key);

		// Constructor
		PukallCipher()
		{
			int j;
			for (j=0;j<=16;j++)	{
				cle[j]=0;
			}
			for (j=0;j<=8;j++)	{
				x1a0[j]=0;
			}

			pkax=0;
			pkbx=0;
			pkcx=0;
			pkdx=0;
			pksi=0;
			pktmp=0;
			x1a2=0;
			pkres=0;
			pki=0;
			inter=0;
			cfc=0;
			cfd=0;
			compte=0;
			pkc=0;

		}

};

void PukallCipher::pkfin()
{
	int j;
			for (j=0;j<=16;j++)	{
				cle[j]=0;
			}
			for (j=0;j<=8;j++)	{
				x1a0[j]=0;
			}

			pkax=0;
			pkbx=0;
			pkcx=0;
			pkdx=0;
			pksi=0;
			pktmp=0;
			x1a2=0;
			pkres=0;
			pki=0;
			inter=0;
			cfc=0;
			cfd=0;
			compte=0;
			pkc=0;

}
void PukallCipher::pkcode()
{

	pkdx=x1a2+pki;
	pkax=x1a0[pki];
	pkcx=0x015a;
	pkbx=0x4e35;

	pktmp=pkax;
	pkax=pksi;
	pksi=pktmp;

	pktmp=pkax;
	pkax=pkdx;
	pkdx=pktmp;

	if (pkax!=0)	{
		pkax=pkax*pkbx;
	}

	pktmp=pkax;
	pkax=pkcx;
	pkcx=pktmp;

	if (pkax!=0)	{
		pkax=pkax*pksi;
		pkcx=pkax+pkcx;
	}

	pktmp=pkax;
	pkax=pksi;
	pksi=pktmp;
	pkax=pkax*pkbx;
	pkdx=pkcx+pkdx;

	pkax++;

	x1a2=pkdx;
	x1a0[pki]=pkax;

	pkres=pkax^pkdx;
	pki++;
}
void PukallCipher::pkassemble(void)
{
	x1a0[0]= ( cle[0]*256 )+ cle[1];
	pkcode();
	inter=pkres;

	x1a0[1]= x1a0[0] ^ ( (cle[2]*256) + cle[3] );
	pkcode();
	inter=inter^pkres;

	x1a0[2]= x1a0[1] ^ ( (cle[4]*256) + cle[5] );
	pkcode();
	inter=inter^pkres;

	x1a0[3]= x1a0[2] ^ ( (cle[6]*256) + cle[7] );
	pkcode();
	inter=inter^pkres;


	x1a0[4]= x1a0[3] ^ ( (cle[8]*256) + cle[9] );
	pkcode();
	inter=inter^pkres;

	x1a0[5]= x1a0[4] ^ ( (cle[10]*256) + cle[11] );
	pkcode();
	inter=inter^pkres;

	x1a0[6]= x1a0[5] ^ ( (cle[12]*256) + cle[13] );
	pkcode();
	inter=inter^pkres;

	x1a0[7]= x1a0[6] ^ ( (cle[14]*256) + cle[15] );
	pkcode();
	inter=inter^pkres;

	pki=0;
}

void PukallCipher::ascii_encrypt128(char *in, char *key)
{
	int count, k=0;
	short pkd, pke;

	pkfin();

	for (count=0;count<16;count++) {
		cle[count]=key[count];
	}
	cle[count]='\0';

	ascCipherText = (char*)malloc(2*plainlen*sizeof(char)+1);
	for (count=0;count<=plainlen-1;count++) {
		pkc=in[count];

		pkassemble();
		cfc=inter>>8;
		cfd=inter&255;

		for (compte=0;compte<=15;compte++) {
			cle[compte]=cle[compte]^pkc;
		}
		pkc = pkc ^ (cfc^cfd);

		pkd =(pkc >> 4);
		pke =(pkc & 15);

		ascCipherText[k] = 0x61+pkd; k++;
		ascCipherText[k] = 0x61+pke; k++;
	}
	ascCipherText[k] = '\0';

}

void PukallCipher::ascii_decrypt128(char *in, char *key)
{
	int count, k=0;
	short pkd, pke;

	pkfin();

	for (count=0;count<16;count++) {
		cle[count]=key[count];
	}
	cle[count]='\0';

	plainText = (char*)malloc(ascipherlen/2*sizeof(char)+1);

	for (count=0;count<ascipherlen/2;count++) {
		pkd =in[k]; k++;
		pke =in[k]; k++;

		pkd=pkd-0x61;
		pkd=pkd<<4;

		pke=pke-0x61;
		pkc=pkd+pke;

		pkassemble();
		cfc=inter>>8;
		cfd=inter&255;

		pkc = pkc ^ (cfc^cfd);

		for (compte=0;compte<=15;compte++)
		{
			cle[compte]=cle[compte]^pkc;
		}
		plainText[count] = pkc;

	}
	plainText[count] = '\0';

}

int main(int argc, char *argv[])
{

	PukallCipher da;
	char *buf, key[17];
	int i, slen;

	strcpy(key, "0123456789abcdef"); // You should change it with hash
	slen = strlen(argv[1]);

	da.plainlen=slen;
	da.ascipherlen=2*da.plainlen;

	da.ascii_encrypt128(argv[1], key);
	puts(da.ascCipherText);
	da.ascii_decrypt128(da.ascCipherText, key);
	puts(da.plainText);

	return 0;
}



