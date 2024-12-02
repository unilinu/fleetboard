package utils

import (
	"errors"
	"fmt"
	"math/big"
	"net"

	v1 "k8s.io/api/core/v1"
)

// GetIndexIPFromCIDR return index ip in the cidr, index start from 1 not 0, because 0 is not a valid ip.
func GetIndexIPFromCIDR(cidr string, index int) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ipA := ip.Mask(ipnet.Mask)
	start := 0
	for start < index && ipnet.Contains(ipA) {
		start++
		inc(ipA)
	}
	if start != index {
		return "", errors.New("your index is out of the cidr")
	}
	// remove network address and broadcast address
	return ipA.String(), nil
}

func inc(ipA net.IP) {
	for j := len(ipA) - 1; j >= 0; j-- {
		ipA[j]++
		if ipA[j] > 0 {
			break
		}
	}
}

func FindClusterAvailableCIDR(networkCIDR string, existingPeers []string) (string, error) {
	clusterNetworkBits, _, err := divideNetworkBits(networkCIDR)
	if err != nil {
		return "", err
	}
	return findAvailableCIDR(networkCIDR, existingPeers, clusterNetworkBits)

}

func FindNodeAvailableCIDR(networkCIDR string, existingPeers []string) (string, error) {
	_, nodeNetworkBits, err := divideNetworkBits(networkCIDR)
	if err != nil {
		return "", err
	}
	return findAvailableCIDR(networkCIDR, existingPeers, nodeNetworkBits)

}

func divideNetworkBits(networkCIDR string) (clusterNetworkBits, nodeNetworkBits int, err error) {
	_, network, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return 0, 0, err
	}

	networkBits, addressBits := network.Mask.Size()
	hostBits := addressBits - networkBits

	switch {
	case hostBits >= 10 && hostBits <= 11:
		clusterNetworkBits = networkBits + 1
		nodeNetworkBits = addressBits - 6
	case hostBits >= 12 && hostBits <= 17:
		clusterNetworkBits = networkBits + 2
		nodeNetworkBits = addressBits - 8
	case hostBits >= 19 && hostBits <= 23:
		clusterNetworkBits = networkBits + 3
		nodeNetworkBits = addressBits - 8
	case hostBits >= 24:
		clusterNetworkBits = networkBits + 4
		nodeNetworkBits = addressBits - 10

	default:
		err = errors.New("invalid network addressBits")
	}

	return
}

func findAvailableCIDR(networkCIDR string, existingPeers []string, networkBits int) (string, error) {
	// Split networkCIDR into 16 size blocks
	hostBits := 32 - networkBits // 主机位数
	_, network, err := net.ParseCIDR(networkCIDR)

	if err != nil {
		return "", err
	}

	// Create a map to store existing CIDRs
	existingCIDRs := make(map[string]bool)
	for _, cidr := range existingPeers {
		// Trim existing CIDR to 16 bits network
		if len(cidr) == 0 {
			continue
		}
		_, ipNet, _ := net.ParseCIDR(cidr)
		ipNet.IP = ipNet.IP.Mask(net.CIDRMask(networkBits, 32))
		existingCIDRs[ipNet.String()] = true
	}

	// Iterate over available blocks and find an unused one
	for i := 0; i <= (1<<hostBits)-1; i++ {
		// Calculate the next CIDR block
		nextIP := big.NewInt(0).SetBytes(network.IP)
		nextIP.Add(nextIP, big.NewInt(int64(i)<<uint(hostBits)))

		// Convert the next IP to string representation
		nextIPStr := net.IP(nextIP.Bytes()).String()
		newCIDR := nextIPStr + "/" + fmt.Sprintf("%d", networkBits)

		// Check if the generated CIDR overlaps with existing ones
		overlapping := false
		for cidr := range existingCIDRs {
			if isOverlappingCIDR(cidr, newCIDR) {
				overlapping = true
				break
			}
		}
		if !overlapping {
			return newCIDR, nil
		}
	}
	return "", fmt.Errorf("no available CIDR found")
}

func isOverlappingCIDR(cidr1, cidr2 string) bool {
	_, ipNet1, _ := net.ParseCIDR(cidr1)
	_, ipNet2, _ := net.ParseCIDR(cidr2)

	return ipNet1.Contains(ipNet2.IP) || ipNet2.Contains(ipNet1.IP)
}

func GetEth0IP(pod *v1.Pod) string {
	for _, podIP := range pod.Status.PodIPs {
		if podIP.IP != "" {
			return podIP.IP
		}
	}
	return ""
}

func IsRunningAndHasIP(pod *v1.Pod) bool {
	if pod.Status.Phase == v1.PodRunning {
		for _, podIP := range pod.Status.PodIPs {
			if podIP.IP != "" {
				return true
			}
		}
	}
	return false
}
