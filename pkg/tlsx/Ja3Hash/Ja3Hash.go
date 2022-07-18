package Ja3Hash

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/open-ch/ja3"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

const (
	snaplen = 65536
)

type Ja3Handler struct {
	Handlers []*pcap.Handle
	Store    *hybrid.HybridMap
}

func New(options *clients.Options) (*Ja3Handler, error) {
	intterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var filter string
	switch {
	case options.Ja3 && options.Ja3s:
		filter = "(tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && ((tcp[((tcp[12] & 0xf0) >>2)+5] = 0x02) || (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01))"
	case options.Ja3:
		filter = "(tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)"
	case options.Ja3s:
		filter = "(tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x02)"
	}
	handlers := make([]*pcap.Handle, 0)
	for _, intf := range intterfaces {
		if intf.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if intf.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}

		handler, err := pcap.OpenLive(intf.Name, snaplen, true, time.Duration(options.Timeout)*time.Second)
		if err != nil {
			return nil, err
		}
		err = handler.SetBPFFilter(filter)
		if err != nil {
			return nil, err
		}
		handlers = append(handlers, handler)
	}
	store, err := hybrid.New(hybrid.DefaultOptions)
	if err != nil {
		return nil, err
	}
	return &Ja3Handler{Handlers: handlers, Store: store}, nil
}
func (j *Ja3Handler) Handle(options *clients.Options) {
	for _, handler := range j.Handlers {
		go func(handler *pcap.Handle, JA3, JA3s bool) {
			packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
			for packet := range packetSource.Packets() {
				if packet.Layer(layers.LayerTypeTCP) != nil {
					if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
						var (
							NetworkLayer  = packet.NetworkLayer()
							DestinationIP = NetworkLayer.NetworkFlow().Dst().String()
						)
						if JA3 {
							j3, err := ja3.ComputeJA3FromSegment(tcp.Payload)
							if err != nil {
								continue
							}
							ja3Hash := j3.GetJA3Hash()
							if ja3Hash != "" {
								if err := j.Store.Set(DestinationIP+"ja3", []byte(ja3Hash)); err != nil {
									continue
								}
							}
						}
						// TODO handle JA3s
						// if JA3s {}
					}
				}
			}
		}(handler, options.Ja3, options.Ja3s)
	}
}
