package main

/*
Case 38: Go 跨作用域 — 全局变量函数引用在函数内调用
全局 var execCmd = exec.Command，在 main 中引用
预期: 检出 CVI-8000
*/
import (
	"os"
	"os/exec"
)

var execCmd = exec.Command

func runCommand(arg string) {
	// 通过全局函数引用调用
	cmd := execCmd("sh", "-c", arg)
	cmd.Run()
}

func main() {
	if len(os.Args) < 2 {
		return
	}
	runCommand(os.Args[1])
}
