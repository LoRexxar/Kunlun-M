package main

/*
Case 39: Go 跨作用域 — 函数参数传递
将 os/exec.Command 作为函数值参数传入
预期: 检出 CVI-8000
*/
import (
	"os"
	"os/exec"
)

func runWith(execFn func(name string, arg ...string) *exec.Cmd, arg string) {
	cmd := execFn("sh", "-c", arg)
	cmd.Run()
}

func main() {
	if len(os.Args) < 2 {
		return
	}
	runWith(exec.Command, os.Args[1])
}
