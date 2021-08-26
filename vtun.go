package main

import (
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/common/osutil"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/net-byte/vtun/client"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/server"
)

func main() {
	config := config.Config{}
	flag.StringVar(&config.CIDR, "c", "172.16.0.1/24", "tun interface CIDR")
	flag.StringVar(&config.LocalAddr, "l", "0.0.0.0:3000", "local address")
	flag.StringVar(&config.ServerAddr, "s", "0.0.0.0:3001", "server address")
	flag.StringVar(&config.Key, "k", "6w9z$C&F)J@NcRfWjXn3r4u7x!A%D*G-", "encryption key")
	flag.StringVar(&config.Protocol, "p", "ws", "protocol ws/udp")
	flag.BoolVar(&config.ServerMode, "S", true, "server mode")
	flag.Parse()
	config.Init()
	switch config.Protocol {
	case "udp":
		if config.ServerMode {
			server.StartUDPServer(config)
		} else {
			client.StartUDPClient(config)
		}
	case "ws":
		if config.ServerMode {
			StartWSServer(config)
		} else {
			client.StartWSClient(config)
		}
	default:
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:    1500,
	WriteBufferSize:   1500,
	EnableCompression: true,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// StartWSServer start ws server
func StartWSServer(config config.Config) {
	// For TAP driver installation for windows, see https://github.com/slackhq/nebula/issues/9#issuecomment-868407261
	iface := CreateTun(config.CIDR)
	c := cache.New(30*time.Minute, 10*time.Minute)
	go tunToWs(iface, c)
	log.Printf("vtun ws server started on %v,CIDR is %v", config.LocalAddr, config.CIDR)
	http.HandleFunc("/way-to-freedom", func(w http.ResponseWriter, r *http.Request) {
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		wsToTunServer(wsConn, iface, c)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello，世界！")
	})

	http.HandleFunc("/ip", func(w http.ResponseWriter, req *http.Request) {
		ip := req.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = strings.Split(req.RemoteAddr, ":")[0]
		}
		resp := fmt.Sprintf("%v", ip)
		io.WriteString(w, resp)
	})

	http.HandleFunc("/register/pick/ip", func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("key")
		if key != config.Key {
			error403(w, req)
			return
		}
		ip, pl := PickClientIP(config.CIDR)
		resp := fmt.Sprintf("%v/%v", ip, pl)
		io.WriteString(w, resp)
	})

	http.HandleFunc("/register/delete/ip", func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("key")
		if key != config.Key {
			error403(w, req)
			return
		}
		ip := req.URL.Query().Get("ip")
		if ip != "" {
			DeleteClientIP(ip)
		}
		io.WriteString(w, "OK")
	})

	http.HandleFunc("/register/keepalive/ip", func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("key")
		if key != config.Key {
			error403(w, req)
			return
		}
		ip := req.URL.Query().Get("ip")
		if ip != "" {
			KeepAliveClientIP(ip)
		}
		io.WriteString(w, "OK")
	})

	http.HandleFunc("/register/list/ip", func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("key")
		if key != config.Key {
			error403(w, req)
			return
		}
		io.WriteString(w, strings.Join(ListClientIP(), "\r\n"))
	})

	http.ListenAndServe(config.LocalAddr, nil)
}

func error403(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte("403 No Permission"))
}

func tunToWs(iface *water.Interface, c *cache.Cache) {
	buffer := make([]byte, 1500)
	for {
		n, err := iface.Read(buffer)
		if err != nil || err == io.EOF || n == 0 {
			continue
		}
		b := buffer[:n]
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := fmt.Sprintf("%v->%v", dstAddr, srcAddr)
		v, ok := c.Get(key)
		if ok {
			b = cipher.XOR(b)
			v.(*websocket.Conn).WriteMessage(websocket.BinaryMessage, b)
		}
	}
}

func wsToTunServer(wsConn *websocket.Conn, iface *water.Interface, c *cache.Cache) {
	defer netutil.CloseWS(wsConn)
	for {
		wsConn.SetReadDeadline(time.Now().Add(time.Duration(30) * time.Second))
		_, b, err := wsConn.ReadMessage()
		if err != nil || err == io.EOF {
			break
		}
		b = cipher.XOR(b)
		if !waterutil.IsIPv4(b) {
			continue
		}
		srcAddr, dstAddr := netutil.GetAddr(b)
		if srcAddr == "" || dstAddr == "" {
			continue
		}
		key := fmt.Sprintf("%v->%v", srcAddr, dstAddr)
		c.Set(key, wsConn, cache.DefaultExpiration)
		iface.Write(b[:])
	}
}

func CreateTun(cidr string) (iface *water.Interface) {
	c := water.Config{DeviceType: water.TUN}
	iface, err := water.New(c)
	if err != nil {
		log.Fatalln("failed to allocate TUN interface:", err)
	}
	log.Println("interface allocated:", iface.Name())
	osutil.ConfigTun(cidr, iface)
	return iface
}

var _register *cache.Cache

func init() {
	_register = cache.New(30*time.Minute, 3*time.Minute)
}

func AddClientIP(ip string) {
	_register.Add(ip, 0, cache.DefaultExpiration)
}

func DeleteClientIP(ip string) {
	_register.Delete(ip)
}

func ExistClientIP(ip string) bool {
	_, ok := _register.Get(ip)
	return ok
}

func KeepAliveClientIP(ip string) {
	if ExistClientIP(ip) {
		_register.Increment(ip, 1)
	} else {
		AddClientIP(ip)
	}
}

func PickClientIP(cidr string) (clientIP string, prefixLength string) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Panicf("error cidr %v", cidr)
	}
	total := addressCount(ipNet) - 3
	index := uint64(0)
	//skip first ip
	ip = incr(ipNet.IP.To4())
	for {
		ip = incr(ip)
		index++
		if index >= total {
			break
		}
		if !ExistClientIP(ip.String()) {
			AddClientIP(ip.String())
			return ip.String(), strings.Split(cidr, "/")[1]
		}
	}
	return "", ""
}

func ListClientIP() []string {
	result := []string{}
	for k := range _register.Items() {
		result = append(result, k)
	}
	return result
}

func addressCount(network *net.IPNet) uint64 {
	prefixLen, bits := network.Mask.Size()
	return 1 << (uint64(bits) - uint64(prefixLen))
}

func incr(IP net.IP) net.IP {
	IP = checkIPv4(IP)
	incIP := make([]byte, len(IP))
	copy(incIP, IP)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}

func checkIPv4(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
