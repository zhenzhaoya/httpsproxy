package main

import (
	"flag"
	"log"
	"net"

	"github.com/zhenzhaoya/httpsproxy"
	"github.com/zhenzhaoya/httpsproxy/config"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "C", "config.json", "config file path")
	flag.Parse()

	c := config.NewConfig(configPath)
	log.Println("listening at: ", c.Addr)
	app := httpsproxy.GetAPP()
	app.Start(c)

}

func checkAdress(adress string) bool {
	_, err := net.ResolveTCPAddr("tcp", adress)
	if err != nil {
		return false
	}
	return true

}
