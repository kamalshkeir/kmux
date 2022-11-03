package ws

import (
	"net/http"
	"time"
)

var FuncBeforeUpgradeWS = func(r *http.Request) bool {
	return true
}

var FuncBeforeUpgradeWSHandler = func(w http.ResponseWriter,r *http.Request) {
}

var DefaultUpgraderKMUX = Upgrader{
	EnableCompression: true,
	ReadBufferSize:    1024,
	WriteBufferSize:   1024,
	HandshakeTimeout:  10 * time.Second,
	CheckOrigin: FuncBeforeUpgradeWS,
}