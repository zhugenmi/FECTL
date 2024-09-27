#include<stdio.h>
#include<time.h>
#include<math.h>
int main(){
	int a=1;
	clock_t start ,end;
	start=clock();
	for(int i=1;i<=10000000;i++)
		a+=i;
	end=clock();
	printf("%lf\n",(double)(end-start)/CLOCKS_PER_SEC);
	return 0;
}
