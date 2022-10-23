package ws

import (
	"net/http"
	"time"
)


var FuncUpgraderOrigin = func(r *http.Request) bool {
	return true
}

var FuncBeforeUpgrade = func(req *http.Request) bool {
	return true
}

var DefaultUpgraderKMUX = Upgrader{
	EnableCompression: true,
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	HandshakeTimeout:  10 * time.Second,
	CheckOrigin: FuncUpgraderOrigin,
}