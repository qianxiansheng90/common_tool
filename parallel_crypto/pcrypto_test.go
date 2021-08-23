package parallel_pcrypto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"

	"common_tool/log_interface"
	"common_tool/parallel_crypto/pdecrypt"
	"common_tool/parallel_crypto/pencrypt"
)

var letterString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func RandSeqString(n int) string {
	b := make([]string, n)
	for i := range b {
		b[i] = string(letterString[rand.Intn(len(letterString))])
	}
	return strings.Join(b, "")
}

func TestPcrypto(t *testing.T) {
	plainText := RandSeqString(1024 * 1024 * 10)
	plainReader := bytes.NewBufferString(plainText)
	// 加密
	var cipherbuffer = new(bytes.Buffer)
	cipherWriter := bufio.NewWriter(cipherbuffer)
	writer, err := pencrypt.NewEncryptWriter(pencrypt.NewENewEncryptWriterArg{
		Key:      "8d06234416fd49ba9e73b93080d4e173",
		Parallel: 10,
		Writer:   cipherWriter,
		Debug:    false,
		Logger:   log_interface.NewLogStdout(),
	})
	if err != nil {
		t.Errorf("new encrypt writer expect nil but error %v", err)
		return
	}
	defer writer.Close()
	if _, err = io.Copy(writer, plainReader); err != nil {
		t.Errorf("encrypt io copy expect nil but error %v", err)
		return
	}
	if err = writer.Close(); err != nil {
		t.Errorf("encrypt close expect nil but error %v", err)
		return
	}
	// 解密
	plainBuffer := new(bytes.Buffer)
	plainWriter := bufio.NewWriter(plainBuffer)
	cipherReader := bufio.NewReader(bytes.NewBuffer(cipherbuffer.Bytes()))
	reader, err := pdecrypt.NewDecryptReader(pdecrypt.NewDecryptReaderArg{
		Key:      "8d06234416fd49ba9e73b93080d4e173",
		Parallel: 10,
		Reader:   cipherReader,
		Debug:    false,
		Logger:   log_interface.NewLogStdout(),
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	defer reader.Close()
	if _, err = io.Copy(plainWriter, reader); err != nil {
		t.Errorf("decrypt io copy expect nil but error %v", err)
		return
	}

	if err = reader.Close(); err != nil {
		t.Errorf("decrypt close expect nil but error %v", err)
		return
	}
	if bytes.Equal([]byte(plainText), plainBuffer.Bytes()) == false {
		t.Errorf("data encrypt and decrypt not equal plain text")
	}
}

func testEncrypt(ioWriter io.Writer, reader io.Reader) {
	writer, err := pencrypt.NewEncryptWriter(pencrypt.NewENewEncryptWriterArg{
		Key:      "8d06234416fd49ba9e73b93080d4e173",
		Parallel: 10,
		Writer:   ioWriter,
		Debug:    false,
		Logger:   log_interface.NewLogStdout(),
	})
	if err != nil {
		return
	}
	defer writer.Close()
	if _, err = io.Copy(writer, reader); err != nil {
		return
	}
	if err = writer.Close(); err != nil {
		return
	}
}
func BenchmarkEncrypt(b *testing.B) {
	plainText := RandSeqString(1024 * 1024 * 10)
	plainReader := bytes.NewBufferString(plainText)
	// 加密
	var cipherbuffer = new(bytes.Buffer)
	cipherWriter := bufio.NewWriter(cipherbuffer)
	for i := 0; i < b.N; i++ {
		testEncrypt(cipherWriter, plainReader)
		// cipherbuffer.Reset()
	}
}
func testDecrypt(plainWriter io.Writer, ioReader io.Reader) {
	reader, err := pdecrypt.NewDecryptReader(pdecrypt.NewDecryptReaderArg{
		Key:      "8d06234416fd49ba9e73b93080d4e173",
		Parallel: 10,
		Reader:   ioReader,
		Debug:    false,
		Logger:   log_interface.NewLogStdout(),
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	defer reader.Close()
	if _, err = io.Copy(plainWriter, reader); err != nil {
		return
	}

	if err = reader.Close(); err != nil {
		return
	}
}
func BenchmarkDecrypt(b *testing.B) {
	plainText := RandSeqString(1024 * 1024 * 10)
	plainReader := bytes.NewBufferString(plainText)
	// 加密
	var cipherbuffer = new(bytes.Buffer)
	cipherWriter := bufio.NewWriter(cipherbuffer)
	writer, err := pencrypt.NewEncryptWriter(pencrypt.NewENewEncryptWriterArg{
		Key:      "8d06234416fd49ba9e73b93080d4e173",
		Parallel: 10,
		Writer:   cipherWriter,
		Debug:    false,
		Logger:   log_interface.NewLogStdout(),
	})
	if err != nil {
		return
	}
	defer writer.Close()
	if _, err = io.Copy(writer, plainReader); err != nil {
		return
	}
	if err = writer.Close(); err != nil {
		return
	}
	// 解密
	plainBuffer := new(bytes.Buffer)
	plainWriter := bufio.NewWriter(plainBuffer)
	cipherReader := bufio.NewReader(bytes.NewBuffer(cipherbuffer.Bytes()))
	for i := 0; i < b.N; i++ {
		testDecrypt(plainWriter, cipherReader)
		plainBuffer.Reset()
	}
}
