package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

func main() {
	log.SetFlags(log.Lshortfile)
	// 默认配置
	ListenAddr := ":666"
	Password := RandPassword()

	// 启动 server 端并监听
	lsServer, err := NewLsServer(Password, ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatalln(lsServer.Listen(func(listenAddr *net.TCPAddr) {
		log.Println(fmt.Sprintf(`
lightsocks-server: 启动成功，配置如下：
服务监听地址：
%s
密码：
%s`, listenAddr, Password))
	}))
}

type LsServer struct {
	Cipher     *Cipher
	ListenAddr *net.TCPAddr
}

// 新建一个服务端
// 服务端的职责是:
// 1. 监听来自本地代理客户端的请求
// 2. 解密本地代理客户端请求的数据，解析 SOCKS5 协议，连接用户浏览器真正想要连接的远程服务器
// 3. 转发用户浏览器真正想要连接的远程服务器返回的数据的加密后的内容到本地代理客户端

func NewLsServer(password string, listenAddr string) (*LsServer, error) {
	bsPassword, err := ParsePassword(password)
	if err != nil {
		return nil, err
	}
	structListenAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &LsServer{
		Cipher:     NewCipher(bsPassword),
		ListenAddr: structListenAddr,
	}, nil

}

// 运行服务端并且监听来自本地代理客户端的请求

func (lsServer *LsServer) Listen(didListen func(listenAddr *net.TCPAddr)) error {
	return ListenEncryptedTCP(lsServer.ListenAddr, lsServer.Cipher, lsServer.handleConn, didListen)
}

// 解 SOCKS5 协议
// https://www.ietf.org/rfc/rfc1928.txt
func (lsServer *LsServer) handleConn(localConn *SecureTCPConn) {
	defer localConn.Close()
	buf := make([]byte, 256)

	/**
	   The localConn connects to the dstServer, and sends a ver
	   identifier/method selection message:
		          +----+----------+----------+
		          |VER | NMETHODS | METHODS  |
		          +----+----------+----------+
		          | 1  |    1     | 1 to 255 |
		          +----+----------+----------+
	   The VER field is set to X'05' for this ver of the protocol.  The
	   NMETHODS field contains the number of method identifier octets that
	   appear in the METHODS field.
	*/
	// 第一个字段VER代表Socks的版本，Socks5默认为0x05，其固定长度为1个字节
	_, err := localConn.DecodeRead(buf)
	// 只支持版本5
	if err != nil || buf[0] != 0x05 {
		return
	}

	/**
	   The dstServer selects from one of the methods given in METHODS, and
	   sends a METHOD selection message:

		          +----+--------+
		          |VER | METHOD |
		          +----+--------+
		          | 1  |   1    |
		          +----+--------+
	*/
	// 不需要验证，直接验证通过
	localConn.EncodeWrite([]byte{0x05, 0x00})

	/**
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/

	// 获取真正的远程服务的地址
	n, err := localConn.DecodeRead(buf)
	// n 最短的长度为7 情况为 ATYP=3 DST.ADDR占用1字节 值为0x0
	if err != nil || n < 7 {
		return
	}

	// CMD代表客户端请求的类型，值长度也是1个字节，有三种类型
	// CONNECT X'01'
	if buf[1] != 0x01 {
		// 目前只支持 CONNECT
		return
	}

	var dIP []byte
	// aType 代表请求的远程服务器地址类型，值长度1个字节，有三种类型
	switch buf[3] {
	case 0x01:
		//	IP V4 address: X'01'
		dIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		//	DOMAINNAME: X'03'
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			return
		}
		dIP = ipAddr.IP
	case 0x04:
		//	IP V6 address: X'04'
		dIP = buf[4 : 4+net.IPv6len]
	default:
		return
	}
	dPort := buf[n-2:]
	dstAddr := &net.TCPAddr{
		IP:   dIP,
		Port: int(binary.BigEndian.Uint16(dPort)),
	}

	// 连接真正的远程服务
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		return
	} else {
		defer dstServer.Close()
		// Conn被关闭时直接清除所有数据 不管没有发送的数据
		dstServer.SetLinger(0)

		// 响应客户端连接成功
		/**
		  +----+-----+-------+------+----------+----------+
		  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		  +----+-----+-------+------+----------+----------+
		  | 1  |  1  | X'00' |  1   | Variable |    2     |
		  +----+-----+-------+------+----------+----------+
		*/
		// 响应客户端连接成功
		localConn.EncodeWrite([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}

	// 进行转发
	// 从 localUser 读取数据发送到 dstServer
	go func() {
		err := localConn.DecodeCopy(dstServer)
		if err != nil {
			// 在 copy 的过程中可能会存在网络超时等 error 被 return，只要有一个发生了错误就退出本次工作
			localConn.Close()
			dstServer.Close()
		}
	}()
	// 从 dstServer 读取数据发送到 localUser，这里因为处在翻墙阶段出现网络错误的概率更大
	(&SecureTCPConn{
		Cipher:          localConn.Cipher,
		ReadWriteCloser: dstServer,
	}).EncodeCopy(localConn)
}


const passwordLength = 256

type password [passwordLength]byte

func init() {
	// 更新随机种子，防止生成一样的随机密码
	rand.Seed(time.Now().Unix())
}

// 采用base64编码把密码转换为字符串
func (password *password) String() string {
	return base64.StdEncoding.EncodeToString(password[:])
}

// 解析采用base64编码的字符串获取密码

func ParsePassword(passwordString string) (*password, error) {
	bs, err := base64.StdEncoding.DecodeString(strings.TrimSpace(passwordString))
	if err != nil || len(bs) != passwordLength {
		return nil, errors.New("不合法的密码")
	}
	password := password{}
	copy(password[:], bs)
	bs = nil
	return &password, nil
}

// 产生 256个byte随机组合的 密码，最后会使用base64编码为字符串存储在配置文件中
// 不能出现任何一个重复的byte位，必须又 0-255 组成，并且都需要包含

func RandPassword() string {
	// 随机生成一个由  0~255 组成的 byte 数组
	intArr := rand.Perm(passwordLength)
	password := &password{}
	for i, v := range intArr {
		password[i] = byte(v)
		if i == v {
			// 确保不会出现如何一个byte位出现重复
			return RandPassword()
		}
	}
	return password.String()
}

type Cipher struct {
	// 编码用的密码
	encodePassword *password
	// 解码用的密码
	decodePassword *password
}

// 加密原数据
func (cipher *Cipher) Encode(bs []byte) {
	for i, v := range bs {
		bs[i] = cipher.encodePassword[v]
	}
}

// 解码加密后的数据到原数据
func (cipher *Cipher) Decode(bs []byte) {
	for i, v := range bs {
		bs[i] = cipher.decodePassword[v]
	}
}

// 新建一个编码解码器
func NewCipher(encodePassword *password) *Cipher {
	decodePassword := &password{}
	for i, v := range encodePassword {
		encodePassword[i] = v
		decodePassword[v] = byte(i)
	}
	return &Cipher{
		encodePassword: encodePassword,
		decodePassword: decodePassword,
	}
}


const (
	bufSize = 1024
)

var bpool sync.Pool

func init() {
	bpool.New = func() interface{} {
		return make([]byte, bufSize)
	}
}
func bufferPoolGet() []byte {
	return bpool.Get().([]byte)
}
func bufferPoolPut(b []byte) {
	bpool.Put(b)
}

// 加密传输的 TCP Socket
type SecureTCPConn struct {
	io.ReadWriteCloser
	Cipher *Cipher
}

// 从输入流里读取加密过的数据，解密后把原数据放到bs里
func (secureSocket *SecureTCPConn) DecodeRead(bs []byte) (n int, err error) {
	n, err = secureSocket.Read(bs)
	if err != nil {
		return
	}
	secureSocket.Cipher.Decode(bs[:n])
	return
}

// 把放在bs里的数据加密后立即全部写入输出流
func (secureSocket *SecureTCPConn) EncodeWrite(bs []byte) (int, error) {
	secureSocket.Cipher.Encode(bs)
	return secureSocket.Write(bs)
}

// 从src中源源不断的读取原数据加密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureTCPConn) EncodeCopy(dst io.ReadWriteCloser) error {
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)
	for {
		readCount, errRead := secureSocket.Read(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := (&SecureTCPConn{
				ReadWriteCloser: dst,
				Cipher:          secureSocket.Cipher,
			}).EncodeWrite(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// 从src中源源不断的读取加密后的数据解密后写入到dst，直到src中没有数据可以再读取
func (secureSocket *SecureTCPConn) DecodeCopy(dst io.Writer) error {
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)
	for {
		readCount, errRead := secureSocket.DecodeRead(buf)
		if errRead != nil {
			if errRead != io.EOF {
				return errRead
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, errWrite := dst.Write(buf[0:readCount])
			if errWrite != nil {
				return errWrite
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// see net.DialTCP
func DialEncryptedTCP(raddr *net.TCPAddr, cipher *Cipher) (*SecureTCPConn, error) {
	remoteConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return nil, err
	}
	// Conn被关闭时直接清除所有数据 不管没有发送的数据
	remoteConn.SetLinger(0)

	return &SecureTCPConn{
		ReadWriteCloser: remoteConn,
		Cipher:          cipher,
	}, nil
}

// see net.ListenTCP
func ListenEncryptedTCP(laddr *net.TCPAddr, cipher *Cipher, handleConn func(localConn *SecureTCPConn), didListen func(listenAddr *net.TCPAddr)) error {
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	if didListen != nil {
		// didListen 可能有阻塞操作
		go didListen(listener.Addr().(*net.TCPAddr))
	}

	for {
		localConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		// localConn被关闭时直接清除所有数据 不管没有发送的数据
		localConn.SetLinger(0)
		go handleConn(&SecureTCPConn{
			ReadWriteCloser: localConn,
			Cipher:          cipher,
		})
	}
}
