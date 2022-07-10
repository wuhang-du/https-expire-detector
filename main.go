package main

import (
	"fmt"
	"net/http"
)

func detect(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	host := req.Form.Get("host")
	fmt.Fprintf(w, "host: %s  hello \n", host)
	p := CreateTlsProbe(host)
	ok, msg, start, end := p.DoProbe()
	if !ok {
		fmt.Fprintf(w, "wrong %s \n", msg)
		return
	}

	fmt.Fprintf(w, "ok host %v %v \n", start, end)
}

func main() {
	http.HandleFunc("/detect", detect)
	http.ListenAndServe(":8090", nil)
}
