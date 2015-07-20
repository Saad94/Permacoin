#include <vector>
#include <sys/stat.h>
#include <iostream>
using namespace std;

#include "src/primitives/block.cpp"
#include "src/uint256.cpp"
#include "src/hash.cpp"

const int 				n 				=1174;	// total no. of segments.
uint256 				filehash			 ;

FILE*  					fp 					 ;  // pointer to the file segments that will be read in and hashed.
struct stat 			status 				 ;	// finding file size
int 					filesize 		=	0;  // size of the buffer
unsigned char* 			buffer 				 ;  // to read the file into
vector<uint256> 		files(n)			 ;
char*					filenamePaddingBuf 	 ;
int 					filenamePadding 	 ;
char* 					filepath 			 ;

string 					baseFilepath	=  "/home/saad/Desktop/Jerasure-1.2/Examples/Coding/";


int main() {
	filenamePaddingBuf = (char*) malloc(sizeof(char)*10);
	filepath = (char*) malloc(sizeof(char)*20 + baseFilepath.length());
	sprintf(filenamePaddingBuf, "%d", n);
	filenamePadding = strlen(filenamePaddingBuf);

	for (int i = 0; i < n; i++) {
		CHash256 hasher;

		sprintf(filepath, "%sPermacoin_%0*d.pdf", baseFilepath.c_str(), filenamePadding, i);
		fp = fopen(filepath, "rb");
		if (fp == NULL) {
			printf("===========================\nERROR: UNABLE TO OPEN FILE.\n\n");
			exit(0);
		}
		if (filesize == 0) {
			stat(filepath, &status);
			filesize = status.st_size;
			buffer = (unsigned char*)malloc(sizeof(unsigned char)*filesize);
		}

		memset((void*)buffer, 0, sizeof(buffer));
		fread((void*)buffer, sizeof(char), sizeof(buffer), fp);
		fclose(fp);
		
		hasher.Write(buffer, sizeof(buffer));
		hasher.Finalize((unsigned char*)&filehash);
		files[i] = filehash;
	}

	for (int i = 0; i < n; i++) {
		cout << "File[" << i << "] = " << files[i].ToString() << "\n";
	}



	return 0;
}