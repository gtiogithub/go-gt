package account

import (
	"log"
	"time"

	"gt.pro/gtio/go-gt/core/address"
	"github.com/fsnotify/fsnotify"
)

type watcher struct {
	addrManger *address.AddressManager
	starting   bool
	running    bool
	quit       chan struct{}
}

func newWatcher(addrManger *address.AddressManager) *watcher {
	return &watcher{
		addrManger: addrManger,
		quit:       make(chan struct{}),
	}
}

func (w *watcher) start() {
	if w.starting || w.running {
		return
	}
	w.starting = true
	go w.loop()
}

func (w *watcher) close() {
	close(w.quit)
}

func (w *watcher) loop() {
	defer func() {
		w.running = false
		w.starting = false
	}()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(w.addrManger.GetKeyDir())
	if err != nil {
		log.Fatal(err)
	}

	w.running = true

	var (
		debounceDuration = 500 * time.Millisecond
		rescanTriggered  = false
		debounce         = time.NewTimer(0)
	)
	// Ignore initial trigger
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()

	for {
		select {
		case <-w.quit:
			return
		case <-watcher.Events:
			if !rescanTriggered {
				debounce.Reset(debounceDuration)
				rescanTriggered = true
			}
		case <-debounce.C:
			w.addrManger.RefreshAddresses()
			rescanTriggered = false
		}
	}
}
