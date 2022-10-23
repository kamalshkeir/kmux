package kmux

import (
	"net/http"
	"sync"

	"github.com/kamalshkeir/kmux/ws"
)


type WsContext struct {
	Ws     *ws.Conn
	Params map[string]string
	Route
	Request *http.Request
}

// ReceiveText receive text from ws and disconnect when stop receiving
func (c *WsContext) ReceiveText() (string, error) {
	_,msgByte,err := c.Ws.ReadMessage()
	if err != nil {
		return "", err
	}
	return string(msgByte), nil
}

// ReceiveJson receive json from ws and disconnect when stop receiving
func (c *WsContext) ReceiveJson() (map[string]any, error) {
	var data map[string]any
	err := c.Ws.ReadJSON(&data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Json send json to the client
func (c *WsContext) Json(data map[string]any) error {
	err := c.Ws.WriteJSON(data)
	if err != nil {
		return err
	}
	return nil
}

// Broadcast send message to all clients in c.Clients
func (c *WsContext) Broadcast(data any) error {
	for _, ws := range c.Route.Clients {
		err := ws.WriteJSON(data)
		if err != nil {
			return err
		}
	}
	return nil
}

// BroadcastExceptCaller send message to all clients in c.Clients
func (c *WsContext) BroadcastExceptCaller(data map[string]any) error {
	for _, ws := range c.Route.Clients {
		if ws != c.Ws {
			err := ws.WriteJSON(data)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Text send text to the client
func (c *WsContext) Text(data string) error {
	err := c.Ws.WriteMessage(ws.BinaryMessage,[]byte(data))
	if err != nil {
		return err
	}
	return nil
}


var mu sync.RWMutex
// RemoveRequester remove the client from Clients list in context
func (c *WsContext) RemoveRequester(name ...string) {
	mu.Lock()
	defer mu.Unlock()
	for k, ws := range c.Route.Clients {
		if len(name) > 1 {
			n := name[0]
			if conn, ok := c.Route.Clients[n]; ok {
				delete(c.Route.Clients, n)
				_ = conn.Close()
			}
		} else {
			if ws == c.Ws {
				if conn, ok := c.Route.Clients[k]; ok {
					delete(c.Route.Clients, k)
					_ = conn.Close()
				}

			}
		}

	}
}

// AddClient add client to clients_list
func (c *WsContext) AddClient(key string) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := c.Route.Clients[key]; !ok {
		c.Route.Clients[key] = c.Ws
	} else {
		for k, ws := range c.Route.Clients {
			if ws == c.Ws {
				c.Route.Clients[k] = c.Ws
			}
		}
	}
	
}
