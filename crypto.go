package fawsecurity

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "errors"
)

var envelopeMagic = []byte("FAWSEC1\x00")

// Seal protects quarantine/report bytes with AES-256-GCM. The password is not stored.
func Seal(plain, password []byte) ([]byte, error) {
    salt:=make([]byte,16); if _,err:=rand.Read(salt);err!=nil{return nil,err}
    key:=pbkdf2(password,salt,200000,32); block,err:=aes.NewCipher(key);if err!=nil{return nil,err}; gcm,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
    nonce:=make([]byte,gcm.NonceSize());if _,err=rand.Read(nonce);err!=nil{return nil,err}
    sealed:=gcm.Seal(nil,nonce,plain,nil); out:=append([]byte{},envelopeMagic...); out=append(out,salt...); out=append(out,nonce...); out=append(out,sealed...); return out,nil
}

func Open(blob, password []byte) ([]byte,error) {
    if len(blob)<len(envelopeMagic)+16+12 || string(blob[:len(envelopeMagic)])!=string(envelopeMagic){return nil,errors.New("invalid FAWSEC envelope")}
    p:=len(envelopeMagic); salt:=blob[p:p+16];p+=16; nonce:=blob[p:p+12];p+=12; key:=pbkdf2(password,salt,200000,32);block,err:=aes.NewCipher(key);if err!=nil{return nil,err};gcm,err:=cipher.NewGCM(block);if err!=nil{return nil,err};return gcm.Open(nil,nonce,blob[p:],nil)
}

func pbkdf2(password,salt []byte, rounds,keyLen int) []byte {
    out:=make([]byte,0,keyLen); for block:=uint32(1);len(out)<keyLen;block++ { mac:=hmac.New(sha256.New,password);mac.Write(salt);var b [4]byte;binary.BigEndian.PutUint32(b[:],block);mac.Write(b[:]);u:=mac.Sum(nil);t:=append([]byte{},u...);for i:=1;i<rounds;i++{mac=hmac.New(sha256.New,password);mac.Write(u);u=mac.Sum(nil);for j:=range t{t[j]^=u[j]}};out=append(out,t...)};return out[:keyLen]
}
