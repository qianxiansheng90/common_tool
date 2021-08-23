package pdecrypt

import "sync"

type decryptChannelData struct {
	lock         sync.RWMutex             // map 锁
	sendChanMap  map[int]chan decryptData // 发送到goroutine的channel
	closeChannel bool                     // 是否已经关闭了
}

func newDecryptChannelData(count int) *decryptChannelData {
	return &decryptChannelData{
		lock:        sync.RWMutex{},
		sendChanMap: make(map[int]chan decryptData),
	}
}
func (c *decryptChannelData) addChannel(seq int, ch chan decryptData) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.sendChanMap[seq] = ch
}
func (c *decryptChannelData) getChannel(seq int) chan decryptData { // 只有一个线程读取,故取消锁
	// c.lock.RLock()
	// defer c.lock.RUnlock()
	return c.sendChanMap[seq]
}
func (c *decryptChannelData) close() {
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
