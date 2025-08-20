#include<stdio.h>
#include<string.h>

void xorCipher(char* text,const char* key){
    int keylen= strlen(key);
    for(int i=0;i<strlen(text);i++){
        text[i]=text[i]^key[i%keylen];
    }
}

int main(){
    char text[100];
    char key[50];
    printf("Enter a message:");
    fgets(text,sizeof(text),stdin);

    //remove newline
    text[strcspn(text,"\n")]=0;

    printf("Enter a single character key:");
    scanf("%c",&key);

    xorCipher(text,key);
    printf("Excrypted text:%s\n",text);

    xorCipher(text,key);
    printf("decrypted text : %s\n",text);

    return 0;

}