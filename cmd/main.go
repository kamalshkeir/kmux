package main

import "github.com/kamalshkeir/kmux"

func main() {
	app := kmux.New()

	app.Get("/*some", func(c *kmux.Context) {
		c.Text(c.Param("some"))
	})

	app.Run(":9313")
}
