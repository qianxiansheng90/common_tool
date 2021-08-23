package pencrypt

import "sync"

type encryptChannelData struct {
	lock         sync.RWMutex             // map 锁
	sendChanMap  map[int]chan encryptData // 发送到goroutine的channel
	closeChannel bool                     // 是否已经关闭了
}

func newEncryptChannelData(count int) *encryptChannelData {
	return &encryptChannelData{
		lock:        sync.RWMutex{},
		sendChanMap: make(map[int]chan encryptData),
	}
}
func (c *encryptChannelData) addChannel(seq int, ch chan encryptData) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.sendChanMap[seq] = ch
}
func (c *encryptChannelData) getChannel(seq int) chan encryptData { // 只有一个线程读取,故取消锁
	// c.lock.RLock()
	// defer c.lock.RUnlock()
	return c.sendChanMap[seq]
}
func (c *encryptChannelData) close() {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.closeChannel == true {
		return
	}
	c.closeChannel = true
	for _, k := range c.sendChanMap {
		close(k)
	}
	return
}
