package pdecrypt

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

type decryptParallel struct {
	seq     int
	stream  cipher.Stream
	dst     io.WriteCloser
	ctx     context.Context
	dstData []byte
	er      *decryptReader
	debug   bool
	logger  log_interface.Logger
}
type decryptData struct {
	dataSeq int64
	data    []byte
	err     error
}
type newDecryptParallelGoroutineArg struct {
	key         []byte
	writer      io.WriteCloser
	dataChannel chan decryptData
	er          *decryptReader
	logger      log_interface.Logger
}

// 新建一个stream
func newDecryptStream(key []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	return cipher.NewOFB(block, iv[:]), nil
}

// 新建一个 reader
func newDecryptParallelGoroutine(seq int, ctx context.Context, arg newDecryptParallelGoroutineArg) error {
	stream, err := newDecryptStream(arg.key)
	if err != nil {
		return err
	}

	e := &decryptParallel{
		seq:     seq,
		stream:  stream,
		dst:     arg.writer,
		ctx:     ctx,
		dstData: make([]byte, bufLen),
		er:      arg.er,
		debug:   arg.er.debug,
		logger:  arg.logger,
	}
	go e.running(ctx, arg.dataChannel)
	return nil
}

// 初始化并行加密
func (r *decryptParallel) running(ctx context.Context, dataChannel chan decryptData) {
	defer r.Log("%d:decrypt goroutine return", r.seq)
	defer r.er.descRunningGoroutine()
	r.Log("start decrypt goroutine %d", r.seq)
	for {
		select {
		case <-ctx.Done():
			return
		case decryptData, ok := <-dataChannel:
			if ok == false {
				r.Log("%d:channel close", r.seq)
				return
			}
			r.Log("%d:receive data %d:%v", r.seq, decryptData.dataSeq, decryptData.err)
			if len(r.dstData) != len(decryptData.data) {
				r.dstData = make([]byte, len(decryptData.data))
			}
			if len(decryptData.data) != 0 {
				// 加密数据
				r.stream.XORKeyStream(r.dstData, decryptData.data)

			}
			// 写入数据
			if _, err := r.write(ctx, decryptData.dataSeq, r.dstData); err != nil {
				r.er.setError(err)
				r.Log("%d:write data error %s", r.seq, err.Error())
				return
			}
			if decryptData.err != nil {
				r.Log("%d:receive error %v,will close writer", r.seq, decryptData.err)
				r.dst.Close()
				return
			}
		}
	}
}

func (r *decryptParallel) write(ctx context.Context, seq int64, data []byte) (int, error) {
	for {
		if r.er.getWriteSeq() == seq {
			r.Log("%d:write data %d:%t", r.seq, seq, r.er.getWriteSeq() == seq)
			defer r.er.incWriteSeq()
			if len(data) > 0 {
				return r.dst.Write(data)
			}
			return 0, nil
		}
		time.Sleep(1 * time.Microsecond)
	}
}

// 打印日志
func (r *decryptParallel) Log(fmtString string, val ...interface{}) {
	if r.debug == true && r.logger != nil {
		r.logger.Debugf("[%s] %s", time.Now().Format(TimeFormatMS), fmt.Sprintf(fmtString, val...))
	}
}
