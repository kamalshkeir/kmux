package bench

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kamalshkeir/kmux"
)

var app = kmux.New()

//var kmu = kmux.New()

func init() {
	app.GET("/", func(c *kmux.Context) {
		c.Text("ok")
	})
	app.GET("/test/:some", func(c *kmux.Context) {
		c.Text("ok " + c.Param("some"))
	})
	app.GET("/test/:some/:another", func(c *kmux.Context) {
		c.Text("ok " + c.Param("some") + " " + c.Param("another"))
	})
	// kmu.GET("/", func(c *kmux.Context) {
	// 	c.Text("ok")
	// })
	// kmu.GET("/test/:some", func(c *kmux.Context) {
	// 	c.Text("ok " + c.Param("some"))
	// })
	// kmu.GET("/test/:some/:another", func(c *kmux.Context) {
	// 	c.Text("ok " + c.Param("some") + " " + c.Param("another"))
	// })
}

func BenchmarkRouter(b *testing.B) {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		b.Fatal(err)
	}

	// Create a new HTTP response recorder
	recorder := httptest.NewRecorder()

	// Run the benchmark b.N times
	for i := 0; i < b.N; i++ {
		// Call the ServeHTTP function with the request and response recorder
		app.ServeHTTP(recorder, req)
	}
}

func BenchmarkRouterWithParam(b *testing.B) {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/test/anything", nil)
	if err != nil {
		b.Fatal(err)
	}

	// Create a new HTTP response recorder
	recorder := httptest.NewRecorder()

	// Run the benchmark b.N times
	for i := 0; i < b.N; i++ {
		// Call the ServeHTTP function with the request and response recorder
		app.ServeHTTP(recorder, req)
	}
}

func BenchmarkRouterWith2Param(b *testing.B) {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/test/anything/more", nil)
	if err != nil {
		b.Fatal(err)
	}

	// Create a new HTTP response recorder
	recorder := httptest.NewRecorder()

	// Run the benchmark b.N times
	for i := 0; i < b.N; i++ {
		// Call the ServeHTTP function with the request and response recorder
		app.ServeHTTP(recorder, req)
	}
}

// func BenchmarkKmux(b *testing.B) {
// 	// Create a new HTTP request
// 	req, err := http.NewRequest("GET", "/", nil)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	// Create a new HTTP response recorder
// 	recorder := httptest.NewRecorder()

// 	// Run the benchmark b.N times
// 	for i := 0; i < b.N; i++ {
// 		// Call the ServeHTTP function with the request and response recorder
// 		kmu.ServeHTTP(recorder, req)
// 	}
// }

// func BenchmarkKmuxWithParam(b *testing.B) {
// 	// Create a new HTTP request
// 	req, err := http.NewRequest("GET", "/test/anything", nil)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	// Create a new HTTP response recorder
// 	recorder := httptest.NewRecorder()

// 	// Run the benchmark b.N times
// 	for i := 0; i < b.N; i++ {
// 		// Call the ServeHTTP function with the request and response recorder
// 		kmu.ServeHTTP(recorder, req)
// 	}
// }

// func BenchmarkKmuxWith2Param(b *testing.B) {
// 	// Create a new HTTP request
// 	req, err := http.NewRequest("GET", "/test/anything/more", nil)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	// Create a new HTTP response recorder
// 	recorder := httptest.NewRecorder()

// 	// Run the benchmark b.N times
// 	for i := 0; i < b.N; i++ {
// 		// Call the ServeHTTP function with the request and response recorder
// 		kmu.ServeHTTP(recorder, req)
// 	}
// }

// BenchmarkRouter-4                6398119               188.3 ns/op            29 B/op          2 allocs/op
// BenchmarkRouterWithParam-4       4636768               272.2 ns/op            60 B/op          2 allocs/op
// BenchmarkRouterWith2Param-4      4083430               289.3 ns/op            64 B/op          2 allocs/op
// BenchmarkKmux-4                  1000000              1049 ns/op             464 B/op          7 allocs/op
// BenchmarkKmuxWithParam-4         1000000              1290 ns/op             869 B/op          9 allocs/op
// BenchmarkKmuxWith2Param-4         393536              2565 ns/op             893 B/op          9 allocs/op
