package main

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

func detect(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	domain := req.Form.Get("domain")
	log.Infof("req is coming,  %s", domain)
	if domain == "" {
		fmt.Fprintf(w, "请输入域名  \n")
		fmt.Fprintf(w, "使用格式是： /detect?domain=www.baidu.com")
		return
	}

	domain = checkDomain(domain)
	detectInfo := GetCache(domain)
	if detectInfo != nil {
		log.Infof("domain: %s hit cache", domain)
		Print(w, domain, detectInfo)
		return
	}

	p := CreateTlsProbe(domain)
	detectInfo = p.DoProbe()
	SetCache(domain, detectInfo)
	Print(w, domain, detectInfo)
}

func Print(w http.ResponseWriter, domain string, info *detectInfo) {
	fmt.Fprintf(w, "感谢使用\n")
	fmt.Fprintf(w, "探测的域名是：%v\n", domain)
	if info.Result {
		fmt.Fprintf(w, "证书有效期，起始时间是：%v \n", info.Start)
		fmt.Fprintf(w, "证书有效期，截止时间是: %v \n", info.End)
	} else {
		fmt.Fprintf(w, "出错了，原因是：%s \n", info.Msg)
	}
	fmt.Fprintf(w, "\n有任何问题,请联系我:duwh@foxmail.com base64编码的手机号: MTMxMjAzMzY3MDU=")
}

func checkDomain(domain string) string {
	// domain:443
	if strings.HasSuffix(domain, ":443") {
		return domain
	}
	return domain + ":443"
}

func homePage(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "迷路了吗，朋友? \n")
	fmt.Fprintf(w, "请输入域名，使用格式是： /detect?domain=www.baidu.com \n")
	fmt.Fprintf(w, "\n有任何问题,请联系我: duwh@foxmail.com base64编码的手机号: MTMxMjAzMzY3MDU=")
}

func main() {
	http.HandleFunc("/detect", detect)
	http.HandleFunc("/", homePage)
	http.ListenAndServe(":8090", nil)
}
