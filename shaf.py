import struct
H0=0xafbcdefb
H1=0x12344566
H2=0x898798cc
H3=0x89343abc
H4=0x3423abcd
def left_rot(n,b):
    return((n<<b)|(n>>(32-b)))&0xFFFFFFFF
def pad(message):
    original_byte_len=len(message)
    original_bit_len=original_byte_len*8
    message+=b'\x80'
    message+=b'\x00'*((56-(original_byte_len+1)%64)%64)
    message +=struct.pack('>Q',original_bit_len)
    return message
def hash(message):
    h0,h1,h2,h3,h4=H0,H1,H2,H3,H4
    message=pad(message)
    for i in range(0,len(message),64):
        chunk=message[i:i+64]
        w=list(struct.unpack('>16I',chunk))+[0]*64
        for j in range(16,80):
             w[j] = left_rot(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        a,b,c,d,e=h0,h1,h2,h3,h4
        for j in range(80):
            if 0<=j<=19:
                f=(a^b)|(b^d)
                k=0xeabcde12
            elif 20<=j<=39:
                f=(a^~b)|(b^d)
                k=0xadbed123
            elif 40<=j<=59:
                f=(b^d)|(b^~d)
                k=0x12345678
            else:
                f=(c^d)|(d^a)
                k=0x124da123
          
            temp=(left_rot(a,5)+f+e+k+w[j])&0xFFFFFFFF
            e=d
            d=c
            c=left_rot(b,30)
            b=a
            a=temp
        h0=(h0+a)&0xFFFFFFFF
        h1=(h1+b)&0xFFFFFFFF
        h2=(h1+c)&0xFFFFFFFF
        h3=(h1+d)&0xFFFFFFFF
        h4=(h1+e)&0xFFFFFFFF
    return struct.pack(">5I",h0,h1,h2,h3,h4)
def sha(message):
    return hash(message).hex()


message=input("").encode()
digest=sha(message)
print(digest)
     
    