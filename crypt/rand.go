package crypt

import (
	"main/config"
	"math/rand"
	"time"
)

func RandomInt(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return min + rand.Intn(max-min)
}

func RandomBytes(length int) []byte {
	rand.Seed(time.Now().UnixNano())
	randBytes := make([]byte, length)
	rand.Read(randBytes)
	return randBytes
}

func RandomAESKey() error {
	config.GlobalKey = make([]byte, 16)
	_, err := rand.Read(config.GlobalKey[:])
	if err != nil {
		return err
	}
	return nil
}
