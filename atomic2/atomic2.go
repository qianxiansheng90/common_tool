/*
DESCRIPTION
封装atomic
包括对数字的基本操作:赋值、自增、自减、替换、增加、获取、转成string
*/

package atomic2

import (
	"fmt"
	"strconv"
	"sync/atomic"
)

type Int64 struct {
	v int64
}

// 测试使用
func PrintAtomic() {
	fmt.Println("atomic2")
}
// 初始化
func NewAtomic() *Int64 {
	return &Int64{0}
}

func (a *Int64) Get() int64 {
	return atomic.LoadInt64(&a.v)
}

func (a *Int64) Set(v int64) {
	atomic.StoreInt64(&a.v, v)
}

func (a *Int64) CompareAndSwap(o, n int64) bool {
	return atomic.CompareAndSwapInt64(&a.v, o, n)
}

func (a *Int64) Swap(v int64) int64 {
	return atomic.SwapInt64(&a.v, v)
}

func (a *Int64) Add(v int64) int64 {
	return atomic.AddInt64(&a.v, v)
}

func (a *Int64) Sub(v int64) int64 {
	return a.Add(-v)
}

func (a *Int64) Incr() int64 {
	return a.Add(1)
}

func (a *Int64) Decr() int64 {
	return a.Add(-1)
}

func (a *Int64) String() string {
	return strconv.FormatInt(a.Get(), 10)
}

