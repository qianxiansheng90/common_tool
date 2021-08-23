package pencrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"time"


	"common_tool/atomic2"
	"common_tool/log_interface"
)

const (
	bufLen = 16 * 1024 // 16k
)

type encryptWriter struct {
	key              []byte               // 加密的key
	parallel         int                  // 加密goroutine并行数
	dst              io.Writer            // 加密的结果写入到哪个writer
	streamWriter     *cipher.StreamWriter // 如果 paralle =0
	chanDataSeq      *atomic2.Int64       // 数据块的序号,分割数据块，将数据块按照channel顺序，发送到channel
	writeOutSeq      *atomic2.Int64       // goroutine需要按照顺序写入到writer
	buff             []byte               // 本地缓存
	bufferLen        int                  // 本地缓存长度
	channelData      *encryptChannelData  // 发送到goroutine的channel
	runningGoroutine *atomic2.Int64       // 当前有多少加密线程的goroutine
	ctx              context.Context      // ctx
	cancel           context.CancelFunc   // 退出信号
	err              error                // 全局错误
	debug            bool                 // 打印日志
	logger           log_interface.Logger // 日志结构体
}
type NewENewEncryptWriterArg struct {
	Key      string               // 加密的key
	Parallel int                  // 加密goroutine并行数
	Writer   io.Writer            // 加密的结果写入到哪个writer
	Debug    bool                 // 打印日志
	Logger   log_interface.Logger // 日志结构体
}

// 新建一个writer
func NewEncryptWriter(arg NewENewEncryptWriterArg) (io.WriteCloser, error) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &encryptWriter{
		key:              []byte(arg.Key),
		parallel:         arg.Parallel,
		dst:              arg.Writer,
		streamWriter:     &cipher.StreamWriter{},
		chanDataSeq:      atomic2.NewAtomic(),
		writeOutSeq:      &atomic2.Int64{},
		buff:             make([]byte, bufLen),
		channelData:      newEncryptChannelData(arg.Parallel),
		runningGoroutine: atomic2.NewAtomic(),
		ctx:              ctx,
		cancel:           cancel,
		err:              nil,
		debug:            arg.Debug,
		logger:           arg.Logger,
	}
	w, err := e.init()
	if err != nil {
		defer cancel()
	}
	return w, err
}

// 初始化:串行加密
func (w *encryptWriter) newEncryptWriter() (io.WriteCloser, error) {
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	w.streamWriter = &cipher.StreamWriter{
		S: stream,
		W: w.dst,
	}
	return w.streamWriter, nil
}

// 初始化并行加密
func (w *encryptWriter) newEncryptParallelWriter() (io.WriteCloser, error) {
	for i := 0; i < w.parallel; i++ {
		encryptDataChan := make(chan encryptData)
		w.Log("start goroutine %d", i)
		if err := newEncryptParallelGoroutine(i, w.ctx, newEncryptParallelGoroutineArg{
			key:         w.key,
			writer:      w.dst,
			dataChannel: encryptDataChan,
			ew:          w,
			logger:      w.logger,
		}); err != nil {
			return nil, err
		}
		w.runningGoroutine.Incr()
		w.channelData.addChannel(i, encryptDataChan)
	}
	return w, nil
}

// 初始化
func (w *encryptWriter) init() (io.WriteCloser, error) {
	if w.parallel == 0 {
		return w.newEncryptWriter()
	}
	w.Log("start encrypt writer parallel %d", w.parallel)
	return w.newEncryptParallelWriter()
}

// 写入数据
func (w *encryptWriter) Write(p []byte) (n int, err error) {
	if w.parallel == 0 {
		return w.streamWriter.Write(p)
	}
	w.Log("main writer data %d", len(p))
	pIdx := 0
	for {
		dataSeq := w.chanDataSeq.Get()
		var ed = encryptData{
			dataSeq: dataSeq,
			data:    make([]byte, bufLen),
		}
		goroutineSeq := int(dataSeq) % w.parallel
		w.Log("main writer data %d goroutine %d", dataSeq, goroutineSeq)
		w.bufferLen, pIdx = mergeBuf(w.buff, w.bufferLen, ed.data, p, pIdx)
		if pIdx == -1 {
			return len(p), w.err
		}
		dataChan := w.channelData.getChannel(goroutineSeq)
		select {
		case dataChan <- ed:
		case <-w.ctx.Done():
			return 0, errors.New("context done")
		}
		w.chanDataSeq.Incr()
	}
}

// 将currentBuffer 和 writeData 中的数据填充到 sendData
func mergeBuf(currentBuffer []byte, currentBufferLen int, sendData, writeData []byte, writeDataStartIdx int) (int, int) {
	remainWriteDataLen := len(writeData[writeDataStartIdx:])
	sendDataLen := len(sendData)
	if currentBufferLen+remainWriteDataLen < sendDataLen { // 剩余的无法填充
		copy(currentBuffer[currentBufferLen:currentBufferLen+remainWriteDataLen], writeData[writeDataStartIdx:])
		currentBufferLen = currentBufferLen + remainWriteDataLen
		return currentBufferLen, -1
	}
	if currentBufferLen > 0 {
		copy(sendData[:currentBufferLen], currentBuffer[:currentBufferLen])
	}
	copy(sendData[currentBufferLen:sendDataLen], writeData[writeDataStartIdx:sendDataLen-currentBufferLen+writeDataStartIdx])
	writeDataStartIdx += sendDataLen - currentBufferLen
	return 0, writeDataStartIdx
}

// close
func (w *encryptWriter) Close() (err error) {
	if w.bufferLen > 0 { // 缓存中还有数据
		dataSeq := w.chanDataSeq.Get()
		var ed = encryptData{
			dataSeq: dataSeq,
			data:    make([]byte, w.bufferLen),
		}
		copy(ed.data, w.buff[:w.bufferLen])
		goroutineSeq := int(dataSeq) % w.parallel
		dataChan := w.channelData.getChannel(goroutineSeq)
		select {
		case dataChan <- ed:
		case <-w.ctx.Done():
			return errors.New("context done")
		}
		w.chanDataSeq.Incr()
		w.bufferLen = 0
	}
	return w.CloseForce()
}

// 异常结束
func (w *encryptWriter) CloseForce() error {
	if w.parallel == 0 {
		if w.streamWriter != nil {
			return w.streamWriter.Close()
		}
		return nil
	}
	// 发送退出信号
	if w.cancel != nil {
		w.cancel()
	}
	// 关闭所有channel
	w.channelData.close()

	// 等待所有线程退出
	if w.parallel > 0 {
		for {
			// 等待所有goourine退出
			if w.runningGoroutine.Get() != 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return w.err
		}
	}
	return w.err
}

// 写入序号:获取
func (w *encryptWriter) getWriteSeq() int64 {
	return w.writeOutSeq.Get()
}

// 写入序号:自增
func (w *encryptWriter) incWriteSeq() {
	w.writeOutSeq.Incr()
}

// 减少running goroutine
func (w *encryptWriter) descRunningGoroutine() {
	w.runningGoroutine.Decr()
}

// 设置全局error
func (w *encryptWriter) setError(err error) {
	w.err = err
}

// 打印日志
func (w *encryptWriter) Log(fmtString string, val ...interface{}) {
	if w.debug == true && w.logger != nil {
		w.logger.Debugf("[%s] %s", time.Now().Format(TimeFormatMS), fmt.Sprintf(fmtString, val...))
	}
}
