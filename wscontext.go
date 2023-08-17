package kmux

import (
	"context"
	"net/http"
	"sync"

	"github.com/kamalshkeir/kmux/ws"
)

type WsContext struct {
	Ws        *ws.Conn
	CtxParams Params
	Clients   map[string]*ws.Conn
	Request   *http.Request
}

// Context return request context
func (c *WsContext) Context() context.Context {
	return c.Request.Context()
}

// User is alias of c.ContextValue
func (c *WsContext) User(key ...ContextKey) (any, bool) {
	var k ContextKey
	if len(key) > 0 {
		k = key[0]
	} else {
		k = ContextKey("user")
	}
	user := c.Request.Context().Value(k)
	if user != nil {
		return user, true
	} else {
		return nil, false
	}
}

// ContextValue return request context value for given key
func (c *WsContext) ContextValue(key ContextKey) (any, bool) {
	user := c.Request.Context().Value(key)
	if user != nil {
		return user, true
	} else {
		return nil, false
	}
}

// ReceiveText receive text from ws and disconnect when stop receiving
func (c *WsContext) ReceiveText() (string, error) {
	_, msgByte, err := c.Ws.ReadMessage()
	if err != nil {
		return "", err
	}
	return string(msgByte), nil
}

func (c *WsContext) Param(paramName string) string {
	for _, v := range c.CtxParams {
		if v.Key == paramName {
			return v.Value
		}
	}
	return ""
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

// Error send json error
func (c *WsContext) Error(msg string) {
	_ = c.Ws.WriteJSON(map[string]any{
		"error": msg,
	})
}

// Broadcast send message to all clients in c.Clients
func (c *WsContext) Broadcast(data any) error {
	for _, ws := range c.Clients {
		err := ws.WriteJSON(data)
		if err != nil {
			return err
		}
	}
	return nil
}

// BroadcastExceptCaller send message to all clients in c.Clients
func (c *WsContext) BroadcastExceptCaller(data map[string]any) error {
	for _, ws := range c.Clients {
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
	err := c.Ws.WriteMessage(ws.BinaryMessage, []byte(data))
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
	for k, ws := range c.Clients {
		if len(name) > 1 {
			n := name[0]
			if conn, ok := c.Clients[n]; ok {
				delete(c.Clients, n)
				_ = conn.Close()
			}
		} else {
			if ws == c.Ws {
				if conn, ok := c.Clients[k]; ok {
					delete(c.Clients, k)
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
	if _, ok := c.Clients[key]; !ok {
		c.Clients[key] = c.Ws
	} else {
		for k, ws := range c.Clients {
			if ws == c.Ws {
				c.Clients[k] = c.Ws
			}
		}
	}

}
