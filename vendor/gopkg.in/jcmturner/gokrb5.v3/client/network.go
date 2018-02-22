package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gopkg.in/jcmturner/dnsutils.v1"
	"gopkg.in/jcmturner/gokrb5.v3/iana/errorcode"
	"gopkg.in/jcmturner/gokrb5.v3/messages"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

func (cl *Client) resolveKDC(realm string, tcp bool) (int, map[int]string, error) {
	kdcs := make(map[int]string)
	var count int

	// Use DNS to resolve kerberos SRV records if configured to do so in krb5.conf.
	if cl.Config.LibDefaults.DNSLookupKDC {
		proto := "udp"
		if tcp {
			proto = "tcp"
		}
		c, addrs, err := dnsutils.OrderedSRV("kerberos", proto, realm)
		if err != nil {
			return count, kdcs, err
		}
		if len(addrs) < 1 {
			return count, kdcs, fmt.Errorf("no KDC SRV records found for realm %s", realm)
		}
		count = c
		for k, v := range addrs {
			kdcs[k] = strings.TrimRight(v.Target, ".") + ":" + strconv.Itoa(int(v.Port))
		}
	} else {
		// Get the KDCs from the krb5.conf an order them randomly for preference.
		var ks []string
		for _, r := range cl.Config.Realms {
			if r.Realm == realm {
				ks = r.KDC
				break
			}
		}
		count = len(ks)
		if count < 1 {
			return count, kdcs, fmt.Errorf("no KDCs defined in configuration for realm %s", realm)
		}
		i := 1
		if count > 1 {
			l := len(ks)
			for l > 0 {
				ri := rand.Intn(l)
				kdcs[i] = ks[ri]
				if l > 1 {
					// Remove the entry from the source slice by swapping with the last entry and truncating
					ks[len(ks)-1], ks[ri] = ks[ri], ks[len(ks)-1]
					ks = ks[:len(ks)-1]
					l = len(ks)
				} else {
					l = 0
				}
				i += 1
			}
		} else {
			kdcs[i] = ks[0]
		}
	}
	return count, kdcs, nil
}

// SendToKDC performs network actions to send data to the KDC.
func (cl *Client) SendToKDC(b []byte, realm string) ([]byte, error) {
	var rb []byte
	if cl.Config.LibDefaults.UDPPreferenceLimit == 1 {
		//1 means we should always use TCP
		rb, errtcp := cl.sendTCP(realm, b)
		if errtcp != nil {
			if e, ok := errtcp.(messages.KRBError); ok {
				return rb, e
			}
			return rb, fmt.Errorf("communication error with KDC via TCP: %v", errtcp)
		}
		return rb, nil
	}
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		//Try UDP first, TCP second
		rb, errudp := cl.sendUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok && e.ErrorCode != errorcode.KRB_ERR_RESPONSE_TOO_BIG {
				// Got a KRBError from KDC
				// If this is not a KRB_ERR_RESPONSE_TOO_BIG we will return immediately otherwise will try TCP.
				return rb, e
			}
			// Try TCP
			r, errtcp := cl.sendTCP(realm, b)
			if errtcp != nil {
				if e, ok := errtcp.(messages.KRBError); ok {
					// Got a KRBError
					return r, e
				}
				return r, fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)", errudp, errtcp)
			}
			rb = r
		}
		return rb, nil
	}
	//Try TCP first, UDP second
	rb, errtcp := cl.sendTCP(realm, b)
	if errtcp != nil {
		if e, ok := errtcp.(messages.KRBError); ok {
			// Got a KRBError from KDC so returning and not trying UDP.
			return rb, e
		}
		rb, errudp := cl.sendUDP(realm, b)
		if errudp != nil {
			if e, ok := errudp.(messages.KRBError); ok {
				// Got a KRBError
				return rb, e
			}
			return rb, fmt.Errorf("failed to communicate with KDC. Attempts made with TCP (%v) and then UDP (%v)", errtcp, errudp)
		}
	}
	return rb, nil
}

func dialKDCUDP(count int, kdcs map[int]string) (conn *net.UDPConn, err error) {
	i := 1
	for i <= count {
		udpAddr, e := net.ResolveUDPAddr("udp", kdcs[i])
		if e != nil {
			err = fmt.Errorf("error resolving KDC address: %v", e)
			return
		}
		conn, err = net.DialUDP("udp", nil, udpAddr)
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Duration(5 * time.Second)))
			return
		}
		i += 1
	}
	err = errors.New("error in getting a UDP connection to any of the KDCs")
	return
}

func dialKDCTCP(count int, kdcs map[int]string) (conn *net.TCPConn, err error) {
	i := 1
	for i <= count {
		tcpAddr, e := net.ResolveTCPAddr("tcp", kdcs[i])
		if e != nil {
			err = fmt.Errorf("error resolving KDC address: %v", e)
			return
		}
		conn, err = net.DialTCP("tcp", nil, tcpAddr)
		if err == nil {
			conn.SetDeadline(time.Now().Add(time.Duration(5 * time.Second)))
			return
		}
		i += 1
	}
	err = errors.New("error in getting a TCP connection to any of the KDCs")
	return
}

// Send the bytes to the KDC over UDP.
func (cl *Client) sendUDP(realm string, b []byte) ([]byte, error) {
	var r []byte
	count, kdcs, err := cl.resolveKDC(realm, false)
	if err != nil {
		return r, err
	}
	conn, err := dialKDCUDP(count, kdcs)
	if err != nil {
		return r, err
	}
	defer conn.Close()
	_, err = conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}
	udpbuf := make([]byte, 4096)
	n, _, err := conn.ReadFrom(udpbuf)
	r = udpbuf[:n]
	if err != nil {
		return r, fmt.Errorf("sending over UDP failed to %s: %v", conn.RemoteAddr().String(), err)
	}
	if len(r) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return checkForKRBError(r)
}

// Send the bytes to the KDC over TCP.
func (cl *Client) sendTCP(realm string, b []byte) ([]byte, error) {
	var r []byte
	count, kdcs, err := cl.resolveKDC(realm, true)
	if err != nil {
		return r, err
	}
	conn, err := dialKDCTCP(count, kdcs)
	if err != nil {
		return r, err
	}
	defer conn.Close()

	/*
		RFC https://tools.ietf.org/html/rfc4120#section-7.2.2
		Each request (KRB_KDC_REQ) and response (KRB_KDC_REP or KRB_ERROR)
		sent over the TCP stream is preceded by the length of the request as
		4 octets in network byte order.  The high bit of the length is
		reserved for future expansion and MUST currently be set to zero.  If
		a KDC that does not understand how to interpret a set high bit of the
		length encoding receives a request with the high order bit of the
		length set, it MUST return a KRB-ERROR message with the error
		KRB_ERR_FIELD_TOOLONG and MUST close the TCP stream.
		NB: network byte order == big endian
	*/
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(b)))
	b = append(buf.Bytes(), b...)

	_, err = conn.Write(b)
	if err != nil {
		return r, fmt.Errorf("error sending to KDC (%s): %v", conn.RemoteAddr().String(), err)
	}

	sh := make([]byte, 4, 4)
	_, err = conn.Read(sh)
	if err != nil {
		return r, fmt.Errorf("error reading response size header: %v", err)
	}
	s := binary.BigEndian.Uint32(sh)

	rb := make([]byte, s, s)
	_, err = io.ReadFull(conn, rb)
	if err != nil {
		return r, fmt.Errorf("error reading response: %v", err)
	}
	if len(rb) < 1 {
		return r, fmt.Errorf("no response data from KDC %s", conn.RemoteAddr().String())
	}
	return checkForKRBError(rb)
}

func checkForKRBError(b []byte) ([]byte, error) {
	var KRBErr messages.KRBError
	if err := KRBErr.Unmarshal(b); err == nil {
		return b, KRBErr
	}
	return b, nil
}
