//projeto de criptografia RSA, grupo: 
//Gabriel Ivo Lins
//João Matheus Nascimento Dias
//Sérgio Augusto de Leite Melo Filho
//Tércio Calazans
//Wemerson da Silva Ancelmo
//codigo levemente alterado

#include <stdio.h>
#include <ctype.h>
#define LLD long long 
#define MENSAGEM_TAM 100000 //tamanho maximo em caracters da mensagem

//funcao para calcular o mdc entre 2 numeros
int mdc(LLD a, LLD b){
  /*
  if(b == 0) return a;
  else return mdc(b, a%b);
  */

  return (b == 0) ? a : mdc(b, a%b);
}

//funcso para verificar se um numero é primo, retorna 1 se sim, retorna 0 caso nao
int primalidade(LLD num){
  /*
  int count = 0;
    
    for(int i=1; i<=num; i++)
        if(num%i == 0) count++;
    
    if(count == 2) return 1;
    else return 0;
    ]*/

    if((num <= 1) || (num%2 == 0) || (num%3 == 0)) return 0;
    if(num <= 3) return 1;

    for(LLD i = 5; i*i <= num; i += 6){
      (num%i == 0 || num%(i+2) == 0) ? return 0 : continue;
    }
    
    return 1;
}

//funcao para encontrar o inverso da congruencia "a mod b" baseado no algoritimo de euclides e igualdade de Bézout;
int euclides_extendido(LLD a, LLD b){
  LLD b_base = b, q, t;
  LLD x0 = 0, x1 = 1;

  if(b == 1) return 1;

  while(a > 1){
    q = a/b;
    t = b;
    b = a%b;
    a = t;
    t = x0;
    x0 = x1 - (q*x0);
    x1 = t;  
  }

  if(x1 <0) x1 += b_base;
  return x1;
}

//funcao que calcula uma funcao enponencia junto a uma congruencia, pegando o resto da divisao.
/*Essa funcao eh a principal, onde a criptografia realmente acontece "n" eh o numero n(multiplicacao de 2 numeors primos) esse eh fixo.
a "c": varia de acordo com a funcao chamada, para a criptografia o numero "c" é do alfabeto baseado na tabela ASCII, no caso desse projeto adaptado para o A/a começar em 2, para a desencriptografia a "c" eh a letra encriptografa, ou seja, que ja passou por esse processo.
o expoente tambem varia, para a criptografia é usado o expoente da chave publica, para desencriptografia é usado o expoente equivalente a da inversao do expoente da chave publica modulo (p-1)(q-1)*/ 
//ps: pode ser feito com recursao, mas dependendo do expoente gasta muito mais memoria

LLD exponenciacao_modular(LLD c, LLD expoente, LLD n){
  LLD i, aux = 1;

  for(i = 0; i < expoente; i++){
  aux = (aux*c)%n;
  }
  return aux;
}


//funcao que faz a adaptacao, essa funcao recebe a mensagem como um string e no processo converte todos os caracteres do alfabeto em minusculo e subtrai 95, na tabel ascci o valor do 'a' é 97, entao 97 - 2 = 95, e como pedido na descricao do projeot o ' ' como 28;
void conversao_primaria(LLD *message_int, char *message, int loop){
  if(message[loop] == '\0' || loop == MENSAGEM_TAM) return;

  int base;

  if(message[loop] != ' '){ 

  base = (int)tolower(message[loop]);
  message_int[loop] = base-95;
  return conversao_primaria(message_int, message, loop+1);
  }else{
    message_int[loop] = 28;
    return conversao_primaria(message_int, message, loop+1);
  }
}

///geracao das chaves n e e(publicas), atraves de p, q e e(privadas) 
void gerador_de_chaves(){

  LLD p, q, e, n, d, n2;

  FILE *public_key, *private_key;
  public_key = fopen("chave_publica.txt", "w");
  private_key = fopen("chave_privada.txt", "w");

  printf("Digite P, Q e E, tal qual, P e Q são primos e E eh coprimo com (p - 1)(q - 1): ");
  scanf("%lld %lld %lld", &p, &q, &e);

    while(!primalidade(p) || !primalidade(q)){
      printf("P ou Q nao eh primo, digite novamente: ");
      scanf("%lld %lld", &p, &q);
      printf("\n");
    }

  n2 = (p-1)*(q-1);

  while(mdc(e, n2) != 1){
    printf("E não é coprimo, digite novamente: ");
    scanf("%lld", &e);
    printf("\n");
  }
    n = p*q;
    d = euclides_extendido(e, n2);

    fprintf(private_key, "p {%lld}\tq {%lld}\td {%lld}", p, q, d);
    fprintf(public_key, "n {%lld}\te {%lld}", n, e);

    fclose(public_key);
    fclose(private_key);
    return;
  }

//funcao que criptografa
void encriptar(){
  FILE *message_raw, *message_encripted;
  message_raw = fopen("Mensagem_para_encriptar.txt", "r");
  message_encripted = fopen("Mensagem_encriptada.txt", "w");

  char message[MENSAGEM_TAM];
  LLD message_convertido[MENSAGEM_TAM];
  LLD n, e, i, aux;
  int tamanho = 0;

  printf("Digite os valores de N e E: ");
  scanf("%lld %lld", &n, &e);

  while(fscanf(message_raw, "%c", &message[tamanho]) != EOF) tamanho++;

  conversao_primaria(message_convertido, message, 0);

  for (i = 0; i < tamanho; i++) {
    printf("Encriptografando [%.2lf%%]\n", (i/(double)tamanho)*100.0);
        aux = exponenciacao_modular(message_convertido[i], e, n);
        fprintf(message_encripted, "%lld ", aux);
    }

  printf("\nEncriptografando....\n");
  printf("Mensagem encriptografa foi salva no arquivo: ""Mensagem_encriptada.txt""\n");

  fclose(message_raw);
  fclose(message_encripted);
  return;
}

//funcao que desencriptografa
void desencriptar(){
 LLD i, base;
 LLD p, q, e, n, n2, d;
 LLD message[MENSAGEM_TAM];
 int tamanho = 0;
 int aux = 0;

 FILE *message_encripted, *message_desencripted;
 message_encripted = fopen("Mensagem_encriptada.txt", "r");
 message_desencripted = fopen("Mensagem_desencriptada.txt", "w");


  printf("Digite P, Q e , E, tal qual, E eh coprimo com (p - 1)(q - 1): ");
  scanf("%lld %lld %lld", &p, &q, &e);

    while(primalidade(p) != 1 || primalidade(q) != 1){
      printf("P ou Q nao eh primo, digite novamente: ");
      scanf("%lld %lld", &p, &q);
      printf("\n");
    }

  n = p*q;
  n2 = (p-1)*(q-1);
  d = euclides_extendido(e, n2);


  while(fscanf(message_encripted, "%lld", &message[tamanho]) != EOF){
    if((char)message[tamanho] != ' ') aux++; 
    tamanho++;
  }

  

  for(i=0; i < aux; i++){
    base = exponenciacao_modular(message[i], d, n);
    printf("Desencriptografando [%.2lf%%]\n", (i/(double)aux)*100.0);
    if(base == 28){
      fprintf(message_desencripted, " ");
    }else{
      fprintf(message_desencripted, "%c", (char)(base+95));
    }
  }

  printf("Mensagem desencriptografa foi salva no arquivo: ""Mensagem_desencriptada.txt""\n");

  fclose(message_encripted);
  fclose(message_desencripted);
}


int main(void) {
  short escolha;

  //inicializacao iniciais de arquivos principais, em caso não iniciar dar erro na hora de ler, alem de facilitar para o usuaria achar os arquivos para digitar

  FILE *inicializacao1 = fopen("Mensagem_para_encriptar.txt", "w");
  FILE *inicializacao2 = fopen("Mensagem_para_desencriptar.txt", "w");
  fclose(inicializacao1);
  fclose(inicializacao2);

  printf("Atencao: Caso queira enciptografar escreva a mensagem no arquivo ""Mensagem_para_encriptar.txt""\n\t\t Caso queiro desencriptografar escreva a mensagem encriptografada no arquivo ""Mensagem_para_desencriptar.txt""\n");

  do{
    printf("\n");
    printf("Escolha uma opcao:\n");
    printf("1-Gerador de chave\n2-Encriptar o arquivo\n3-Desencriptar o arquivo\n4-Sair\n---");
    scanf("%hd", &escolha);
    printf("\n");

    switch(escolha){
      case 1: gerador_de_chaves(); break;
      case 2: encriptar(); break;
      case 3: desencriptar(); break;
      case 4: return 0;
    }

  }while(escolha != 4);
}
