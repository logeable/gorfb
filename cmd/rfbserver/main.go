package main

import (
	"log"

	"github.com/logeable/gorfb/rfb"
	"github.com/logeable/gorfb/utils"
)

func main() {
	server := rfb.NewServer()
	go func() {
		log.Fatal(server.ListenAndServe(":5900"))
	}()

	if err := utils.GracefullShutdown(server); err != nil {
		log.Fatalf("shutdown server failed: %s", err)
	}
	log.Println("shutdown server successfully")
}
