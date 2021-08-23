package pencrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"time"

	"common_tool/log_interface"
)

const (
	TimeFormatMS = "2006-01-02 15:04:05.000" // 时间带毫秒
)

type encryptParallel struct {
	seq     int
	stream  cipher.Stream
	dst     io.Writer
	ctx     context.Context
	dstData []byte
	ew      *encryptWriter
	debug   bool
	logger  log_interface.Logger
}
type encryptData struct {
	dataSeq int64
	data    []byte
}
type newEncryptParallelGoroutineArg struct {
	key         []byte
	writer      io.Writer
	dataChannel chan encryptData
	ew          *encryptWriter
	logger      log_interface.Logger
}

// 新建一个stream
func newEncryptStream(key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	return cipher.NewOFB(block, iv[:]), nil
}

// 新建一个writer
func newEncryptParallelGoroutine(seq int, ctx context.Context, arg newEncryptParallelGoroutineArg) error {
	stream, err := newEncryptStream(arg.key)
	if err != nil {
		return err
	}
	e := &encryptParallel{
		seq:     seq,
		stream:  stream,
		dst:     arg.writer,
		ctx:     ctx,
		dstData: make([]byte, bufLen),
		ew:      arg.ew,
		debug:   arg.ew.debug,
		logger:  arg.logger,
	}
	go e.running(ctx, arg.dataChannel)
	return nil
}

// 初始化并行加密
func (w *encryptParallel) running(ctx context.Context, dataChannel chan encryptData) {
	defer w.Log("%d:encrypt goroutine return", w.seq)
	defer w.ew.descRunningGoroutine()
	for {
		select {
		case <-ctx.Done():
			return
		case encryptData, ok := <-dataChannel:
			if ok == false {
				w.Log("%d:channel close", w.seq)
				return
			}
			w.Log("%d:receive data seq %d data len %d", w.seq, encryptData.dataSeq, len(encryptData.data))
			if len(w.dstData) != len(encryptData.data) {
				w.dstData = make([]byte, len(encryptData.data))
			}
			// 加密数据
			w.stream.XORKeyStream(w.dstData, encryptData.data)
			// 写入数据
			if _, err := w.write(ctx, encryptData.dataSeq, w.dstData); err != nil {
				w.ew.setError(err)
				w.Log("%d:write data error %s", w.seq, err.Error())
				return
			}
		}
	}
}

func (w *encryptParallel) write(ctx context.Context, seq int64, data []byte) (int, error) {
	for {
		if w.ew.getWriteSeq() == seq {
			w.Log("%d:write data %d:%t", w.seq, seq, w.ew.getWriteSeq() == seq)
			defer w.ew.incWriteSeq()
			if len(data) > 0 {
				return w.dst.Write(data)
			}
			return 0, nil
		}
		time.Sleep(1 * time.Microsecond)
	}
}

// 打印日志
func (w *encryptParallel) Log(fmtString string, val ...interface{}) {
	if w.debug == true && w.logger != nil {
		w.logger.Debugf("[%s] %s", time.Now().Format(TimeFormatMS), fmt.Sprintf(fmtString, val...))
	}
}
