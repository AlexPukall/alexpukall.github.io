/*-------------------------------------------------*/
/*                CryptFile program                */
/*	    For Encrypt and Decrypt File           */
/*           |With PC1 Cipher Algorithm|           */
/*           |By Alexander PUKALL 1991|            */
/*                                                 */
/*              Software by HacKSpideR             */
/*                     Enjoy ;)                    */
/*-------------------------------------------------*/
#include <stdio.h>
#include <string.h>
/*Global variable*/
unsigned short ax,bx,cx,dx,si,tmp,x1a2,x1a0[16],res,i,inter,cfc,cfd,compte;
unsigned char cle[32]; /* les variables sont definies de facon globale */
unsigned char buff[32];
short c;
int c1,count;
short d,e;
FILE *in,*out;
/*End global variable*/
/*Function def*/
int fin();
int assemble();
int code();

int main(int argc,char *argv[]){
	if(!argv[1] || (!strcmp(argv[1],"-h")) || !argv[2]){
		printf("NAME :\n");
		printf("	CryptFile - Encrypt and Decrypt File with PC1 Cipher Algorithm\n");
		printf("SYNOPSIS :\n");
		printf("	-c file_name [outputfile]	for encrypt a file\n");
		printf("	-d file_name [outputfile]	for decrypt a file\n");
		printf("Key size : 256 bits\n");
		printf("Defaut output file name is \"output.bin\"\n");
		return 0;
	}
	if(!strcmp(argv[1],"-c")){
		printf("Encrypt : %s\n",argv[2]);
		strcpy(cle,"abcdefghijklmnopqrstuvwxyz012345");
		printf("Enter a key : ");
		scanf("%32s",cle);	
		if((in = fopen(argv[2],"rb")) == NULL){printf("Error file doesn't exist\n");return 1;}
		if(!argv[3]){
			if((out = fopen("output.bin","wb")) == NULL){printf("Error file can't be create\n");return 1;}
		}else{
			if((out = fopen(argv[3],"wb")) == NULL){printf("Error file doesn't exist\n");return 1;}
		}
		while ( (c=fgetc(in)) != EOF){/* c contains the byte read in the file */
			assemble();
			cfc=inter>>8;
			cfd=inter&255; /* cfc^cfd = random byte */

			/* K ZONE !!!!!!!!!!!!! */
			/* here the mix of c and cle[compte] is before the encryption of c */
			for (compte=0;compte<=31;compte++){
				/* we mix the plaintext byte with the key */
				cle[compte]=cle[compte]^c;
			}
			c = c ^ (cfc^cfd);

			d=(c >> 4); /* we split the 'c' crypted byte into two 4 bits parts 'd' and 'e' */
			e=(c & 15);

			fputc(0x61+d,out); /*we write the two 4 bits parts as ASCII letters */
			fputc(0x61+e,out);
		}
		fclose(in);fclose(out);fin();
		printf("\nEncryption done !\n");
		return 0;
	}
	if(!strcmp(argv[1],"-d")){
		printf("Decrypt : %s\n",argv[2]);
		strcpy(cle,"abcdefghijklmnopqrstuvwxyz012345");
		printf("Enter a key : ");
		scanf("%32s",cle);
		if((in = fopen(argv[2],"rb")) == NULL){printf("Error file doesn't exist\n");return 1;}
		if(!argv[3]){
			if((out = fopen("output.bin","wb")) == NULL){printf("Error file can't be create\n");return 1;}
		}else{
			if((out = fopen(argv[3],"wb")) == NULL){printf("Error file doesn't exist\n");return 1;}
		}
		while ( (d=fgetc(in)) != EOF){ /* read the first letter in the file */
			e=fgetc(in); /* read the second letter in the file */
			d=d-0x61; /* retrieve the 4 bits from the first letter */
			d=d<<4;

			e=e-0x61; /* retrieve the 4 bits from the second letter */
			c=d+e; /* 4 bits of the first letter + 4 bits of the second = 8 bits */

			assemble();
			cfc=inter>>8;
			cfd=inter&255; /* cfc^cfd = random byte */

			/* K ZONE !!!!!!!!!!!!! */
			/* here the mix of c and cle[compte] is after the decryption of c */
			c = c ^ (cfc^cfd);

			for (compte=0;compte<=31;compte++){
				/* we mix the plaintext byte with the key */
				cle[compte]=cle[compte]^c;
			}
			fputc(c,out); /* we write the decrypted byte in the file IN.BIN */
		}
		fclose(in);fclose(out);fin();
		printf("\nDecryption done !\n");
		return 0;
	}
	printf("Enter :\n	-h for help\n");
	return 0;	
}

int code(){
dx=x1a2+i;
ax=x1a0[i];
cx=0x015a;
bx=0x4e35;

tmp=ax;
ax=si;
si=tmp;

tmp=ax;
ax=dx;
dx=tmp;

if (ax!=0){
	ax=ax*bx;
}

tmp=ax;
ax=cx;
cx=tmp;

if (ax!=0){
	ax=ax*si;
	cx=ax+cx;
}

tmp=ax;
ax=si;
si=tmp;
ax=ax*bx;
dx=cx+dx;

ax=ax+1;

x1a2=dx;
x1a0[i]=ax;

res=ax^dx;
i=i+1;
return 0;
}
int assemble(){

x1a0[0]= ( cle[0]*256 )+ cle[1];
code();
inter=res;

x1a0[1]= x1a0[0] ^ ( (cle[2]*256) + cle[3] );
code();
inter=inter^res;

x1a0[2]= x1a0[1] ^ ( (cle[4]*256) + cle[5] );
code();
inter=inter^res;

x1a0[3]= x1a0[2] ^ ( (cle[6]*256) + cle[7] );
code();
inter=inter^res;

x1a0[4]= x1a0[3] ^ ( (cle[8]*256) + cle[9] );
code();
inter=inter^res;

x1a0[5]= x1a0[4] ^ ( (cle[10]*256) + cle[11] );
code();
inter=inter^res;

x1a0[6]= x1a0[5] ^ ( (cle[12]*256) + cle[13] );
code();
inter=inter^res;

x1a0[7]= x1a0[6] ^ ( (cle[14]*256) + cle[15] );
code();
inter=inter^res;

x1a0[8]= x1a0[7] ^ ( (cle[16]*256) + cle[17] );
code();
inter=inter^res;

x1a0[9]= x1a0[8] ^ ( (cle[18]*256) + cle[19] );
code();
inter=inter^res;

x1a0[10]= x1a0[9] ^ ( (cle[20]*256) + cle[21] );
code();
inter=inter^res;

x1a0[11]= x1a0[10] ^ ( (cle[22]*256) + cle[23] );
code();
inter=inter^res;

x1a0[12]= x1a0[11] ^ ( (cle[24]*256) + cle[25] );
code();
inter=inter^res;

x1a0[13]= x1a0[12] ^ ( (cle[26]*256) + cle[27] );
code();
inter=inter^res;

x1a0[14]= x1a0[13] ^ ( (cle[28]*256) + cle[29] );
code();
inter=inter^res;

x1a0[15]= x1a0[14] ^ ( (cle[30]*256) + cle[31] );
code();
inter=inter^res;

i=0;
return 0;
}
int fin(){
/* erase all variables */
for (compte=0;compte<=31;compte++){
	cle[compte]=0;
}
ax=0;
bx=0;
cx=0;
dx=0;
si=0;
tmp=0;
x1a2=0;
x1a0[0]=0;
x1a0[1]=0;
x1a0[2]=0;
x1a0[3]=0;
x1a0[4]=0;
res=0;
i=0;
inter=0;
cfc=0;
cfd=0;
compte=0;
c=0;
return 0;
}