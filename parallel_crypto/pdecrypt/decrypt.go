package pdecrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"time"

	"common_tool/atomic2"
	"common_tool/log_interface"
)

const (
	bufLen = 16 * 1024 // 16k
)

type decryptReader struct {
	key                []byte               // 解密key
	parallel           int                  // 解密goroutine的并行数
	reader             io.Reader            // reader:读取数据
	streamReader       *cipher.StreamReader // 如果parallel =0使用流式解密
	chanDataSeq        *atomic2.Int64       // 数据块的序号,分割数据块，将数据块按照channel顺序，发送到channel
	writeOutSeq        *atomic2.Int64       // goroutine需要按照顺序写入到writer
	runningGoroutine   *atomic2.Int64       // 当前有多少goroutine在运行
	buff               []byte               // 本地缓存
	bufferLen          int                  // 本地缓存长度
	decryptChannelData *decryptChannelData  // 发送到解密goroutine的channel
	channelDataReader  io.ReadCloser        // 从解密goroutine中汇总出来的数据流读取
	debug              bool                 // 开启日志
	logger             log_interface.Logger // 日志输出
	ctx                context.Context      // ctx
	cancel             context.CancelFunc   // 退出信号
	err                error                // 全局error
}
type NewDecryptReaderArg struct {
	Key      string               // 解密key
	Parallel int                  // 解密goroutine的并行数
	Reader   io.Reader            // reader:读取数据
	Debug    bool                 // 开启日志
	Logger   log_interface.Logger // 日志输出
}

func NewDecryptReader(arg NewDecryptReaderArg) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &decryptReader{
		key:                []byte(arg.Key),
		parallel:           arg.Parallel,
		reader:             arg.Reader,
		streamReader:       &cipher.StreamReader{},
		chanDataSeq:        atomic2.NewAtomic(),
		writeOutSeq:        atomic2.NewAtomic(),
		runningGoroutine:   atomic2.NewAtomic(),
		buff:               make([]byte, bufLen),
		bufferLen:          0,
		decryptChannelData: newDecryptChannelData(arg.Parallel),
		channelDataReader:  nil,
		debug:              arg.Debug,
		logger:             arg.Logger,
		ctx:                ctx,
		cancel:             cancel,
		err:                nil,
	}
	r, err := d.init()
	if err != nil {
		defer cancel()
	}
	return r, err
}

// 读取数据
func (r *decryptReader) init() (io.ReadCloser, error) {
	if r.parallel == 0 {
		return r.newDecryptReader()
	}
	r.Log("start encrypt writer parallel %d", r.parallel)
	return r.newEncryptParallelReader()
}

// 初始化:串行解密
func (r *decryptReader) newDecryptReader() (io.ReadCloser, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	r.streamReader = &cipher.StreamReader{
		S: stream,
		R: r.reader,
	}
	return r, nil
}

// 初始化并行解密
func (r *decryptReader) newEncryptParallelReader() (io.ReadCloser, error) {
	reader, writer := io.Pipe()
	for i := 0; i < r.parallel; i++ {
		decryptDataChan := make(chan decryptData)
		if err := newDecryptParallelGoroutine(i, r.ctx, newDecryptParallelGoroutineArg{
			key:         r.key,
			writer:      writer,
			dataChannel: decryptDataChan,
			er:          r,
			logger:      r.logger,
		}); err != nil {
			return nil, err
		}
		r.runningGoroutine.Incr()
		r.decryptChannelData.addChannel(i, decryptDataChan)
	}
	r.runningGoroutine.Incr()
	go r.readGoroutine()
	r.channelDataReader = reader
	return r, nil
}

// 读取数据
func (r *decryptReader) readGoroutine() {
	// 读取数据
	// 分割数据块，并发送给channel
	defer r.Log("reader goroutine return")
	defer r.descRunningGoroutine()
	r.Log("start reader goroutine")
	p := make([]byte, bufLen)
	var totalReadSize int64 = 0
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}
		size, err := r.reader.Read(p)
		totalReadSize += int64(size)
		r.Log("reader read data %d", size)
		if size > 0 {
			// 处理数据
			r.handlerData(p[:size])
		}
		if err != nil && err.Error() == io.EOF.Error() { // 读到末尾了
			r.Log("reader goroutine read finish total size %d", totalReadSize)
			r.handlerBuffer()
			return
		}
		if err != nil { // 遇到错误
			r.err = err
			return
		}
	}
}

// 处理数据
func (r *decryptReader) handlerData(p []byte) {
	var readSize int
	var dd = decryptData{
		dataSeq: 0,
		data:    make([]byte, bufLen),
	}
	r.bufferLen, readSize = splitBuffer(r.buff, r.bufferLen, p, dd.data)
	if readSize == -1 {
		return
	}
	dd.dataSeq = r.chanDataSeq.Get()
	sendDataSeq := dd.dataSeq % int64(r.parallel)
	c := r.decryptChannelData.getChannel(int(sendDataSeq))
	r.Log("reader goroutine send channel %d", sendDataSeq)
	r.sendChannelData(c, dd)
	r.chanDataSeq.Incr()
}

// 处理buffer
func (r *decryptReader) handlerBuffer() {
	var dd = decryptData{
		dataSeq: r.chanDataSeq.Get(),
		data:    make([]byte, r.bufferLen),
		err:     io.EOF,
	}
	if r.bufferLen > 0 {
		// 拷贝数据
		copy(dd.data[:r.bufferLen], r.buff[:r.bufferLen])
	}

	sendDataSeq := dd.dataSeq % int64(r.parallel)
	c := r.decryptChannelData.getChannel(int(sendDataSeq))
	r.Log("reader goroutine send finish to channel %d", sendDataSeq)
	r.sendChannelData(c, dd)
	r.chanDataSeq.Incr()
	r.decryptChannelData.close()
}

// 发送数据
func (r *decryptReader) sendChannelData(c chan decryptData, data decryptData) {
	for {
		if r.err != nil {
			return
		}
		select {
		case <-r.ctx.Done():
			return
		case c <- data:
			return
		}
	}
}

// 读取数据
func (r *decryptReader) Read(p []byte) (n int, err error) {
	if r.parallel == 0 {
		return r.streamReader.Read(p)
	}
	size, err := r.channelDataReader.Read(p)
	r.Log("main read data %d error %v", size, err)
	if r.err != nil {
		return 0, r.err
	}
	return size, err
}

// 将currentBuffer 和 readData 中的数据填充到 sendData
func splitBuffer(currentBuffer []byte, currentBufferLen int, readData []byte, sendData []byte) (int, int) {
	readDataLen := len(readData)
	sendDataLen := len(sendData)
	if currentBufferLen+readDataLen < sendDataLen { // 剩余的无法填充
		copy(currentBuffer[currentBufferLen:currentBufferLen+readDataLen], readData[:])
		currentBufferLen += readDataLen
		return currentBufferLen, -1
	}
	if currentBufferLen > 0 {
		copy(sendData[:currentBufferLen], currentBuffer[:currentBufferLen])
	}
	remainReadDataLen := sendDataLen - currentBufferLen
	copy(sendData[currentBufferLen:], readData[:remainReadDataLen])
	copy(currentBuffer[:readDataLen-remainReadDataLen], readData[remainReadDataLen:])
	return readDataLen - remainReadDataLen, 0
}

// close
func (r *decryptReader) Close() (err error) {
	if r.parallel == 0 {
		return nil
	}
	// 发送退出信号
	if r.cancel != nil {
		r.cancel()
	}
	// 关闭所有channel
	r.decryptChannelData.close()
	// 等待所有线程退出
	if r.parallel > 0 {
		for {
			// 等待所有goourine退出
			if r.runningGoroutine.Get() != 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return
		}
	}
	if r.channelDataReader != nil {
		r.channelDataReader.Close()
	}
	return r.err
}

// 写入到writer的序号:获取
func (r *decryptReader) getWriteSeq() int64 {
	return r.writeOutSeq.Get()
}

// 写入到writer的序号:自增
func (r *decryptReader) incWriteSeq() {
	r.writeOutSeq.Incr()
}

// 减少running goroutine
func (r *decryptReader) descRunningGoroutine() {
	r.runningGoroutine.Decr()
}

// 设置全局error
func (r *decryptReader) setError(err error) {
	r.err = err
}

// 打印日志
func (r *decryptReader) Log(fmtString string, val ...interface{}) {
	if r.debug == true && r.logger != nil {
		r.logger.Debugf("[%s] %s", time.Now().Format(TimeFormatMS), fmt.Sprintf(fmtString, val...))
	}
}
