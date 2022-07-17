package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Cache struct {
	sync.RWMutex
	CacheInfo map[string]*TlsInfo
}

type TlsInfo struct {
	ExpireTime int64
	Info       *detectInfo
}

var GlobalCache *Cache
var ConfigTimeout int64 = 3600 * 24 //second; one day

func init() {
	GlobalCache = &Cache{
		CacheInfo: make(map[string]*TlsInfo),
	}

	go func() {
		for {
			time.Sleep(time.Hour)
			var timeOutHost []string
			nowStamp := time.Now().Unix()
			GlobalCache.RLock()
			for k, v := range GlobalCache.CacheInfo {
				if nowStamp > v.ExpireTime {
					timeOutHost = append(timeOutHost, k)
				}
			}
			GlobalCache.RUnlock()

			GlobalCache.Lock()
			for _, v := range timeOutHost {
				delete(GlobalCache.CacheInfo, v)
			}
			GlobalCache.Unlock()

			if len(timeOutHost) != 0 {
				log.Infof("delete %+v", timeOutHost)
			}
		}
	}()
}

func GetCache(host string) *detectInfo {
	GlobalCache.RLock()
	defer GlobalCache.RUnlock()
	info, ok := GlobalCache.CacheInfo[host]
	if !ok {
		return nil
	}
	return info.Info
}

func SetCache(host string, info *detectInfo) {
	ti := &TlsInfo{
		ExpireTime: time.Now().Unix() + ConfigTimeout,
		Info:       info,
	}
	GlobalCache.Lock()
	GlobalCache.CacheInfo[host] = ti
	GlobalCache.Unlock()
}
