package kmux

import (
	"sync"

	"github.com/kamalshkeir/kmux/ws"
)


type WsContext struct {
	Ws     *ws.Conn
	Params map[string]string
	Route
	mu     sync.RWMutex
}

// ReceiveText receive text from ws and disconnect when stop receiving
func (c *WsContext) ReceiveText() (string, error) {
	c.mu.RLock()
	_,msgByte,err := c.Ws.ReadMessage()
	if err != nil {
		c.mu.Unlock()
		return "", err
	}
	c.mu.RUnlock()
	return string(msgByte), nil
}

// ReceiveJson receive json from ws and disconnect when stop receiving
func (c *WsContext) ReceiveJson() (map[string]any, error) {
	var data map[string]any
	c.mu.RLock()
	err := c.Ws.ReadJSON(&data)
	if err != nil {
		c.mu.RUnlock()
		return nil, err
	}
	c.mu.RUnlock()
	return data, nil
}

// Json send json to the client
func (c *WsContext) Json(data map[string]any) error {
	c.mu.Lock()
	err := c.Ws.WriteJSON(data)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	return nil
}

// Broadcast send message to all clients in c.Clients
func (c *WsContext) Broadcast(data any) error {
	c.mu.Lock()
	for _, ws := range c.Route.Clients {
		err := ws.WriteJSON(data)
		if err != nil {
			c.mu.Unlock()
			return err
		}
	}
	c.mu.Unlock()
	return nil
}

// BroadcastExceptCaller send message to all clients in c.Clients
func (c *WsContext) BroadcastExceptCaller(data map[string]any) error {
	c.mu.Lock()
	for _, ws := range c.Route.Clients {
		if ws != c.Ws {
			err := ws.WriteJSON(data)
			if err != nil {
				c.mu.Unlock()
				return err
			}
		}
	}
	c.mu.Unlock()
	return nil
}

// Text send text to the client
func (c *WsContext) Text(data string) error {
	c.mu.Lock()
	err := c.Ws.WriteMessage(ws.BinaryMessage,[]byte(data))
	if err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	return nil
}

// RemoveRequester remove the client from Clients list in context
func (c *WsContext) RemoveRequester(name ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	c.mu.Lock()
	defer c.mu.Unlock()
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
