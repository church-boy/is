alphabet="abcdefghijklmnopqrstuvwxyz"
def mul_inv(x,y):
    if x>y:
        a,b=x,y
    else:
        a,b=y,x
    t1,t2=0,1
    while b!=0:
        q=a//b
        r=a%b
        t=t1-(q*t2)

        a,b=b,r
        t1,t2=t2,t
    if a==1:
        return t1 if t1>0 else t1+y
    else:
        print("no multi")
        return -1
def repeatedsquare(a,b,n):
    res=1
    for i in range(1,b+1):
        res=(res*a)%n
    return res
def key_gen(p,q,e):
    fin=(p-1)*(q-1)
    d=mul_inv(e,fin)
    return d
def encryption(msg,e,n):
    c=repeatedsquare(msg,e,n)
    return c
def decrption(c_ind,d,n):
    msg_index=repeatedsquare(c_ind,d,n)
    return alphabet[msg_index]
key=key_gen(7,11,13)
print(key)
msg=input("enter the msg")
msg_i=alphabet.index(msg)
cipher=encryption(msg_i,7,11)
print(cipher)
c_index=6
plain=decrption(c_index,37,11)
print(plain)