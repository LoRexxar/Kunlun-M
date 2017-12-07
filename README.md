<big>**写在最前，Cobra-W仍然处于测试开发阶段，未发布正式版本，谨慎应用...**</big>

# Cobra-W
[![GitHub (pre-)release](https://img.shields.io/github/release/LoRexxar/Cobra-W/all.svg)](https://github.com/LoRexxar/Cobra-W/releases)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://github.com/wufeifei/cobra/blob/master/LICENSE)


## Introduction（介绍）
Cobra是一款**源代码安全审计**工具，支持检测多种开发语言源代码中的**大部分显著**的安全问题和漏洞。
[https://github.com/wufeifei/cobra](https://github.com/wufeifei/cobra)

Cobra-W是从Cobra2.0发展而来的分支，着眼于白帽子使用的白盒审计工具，将工具重心从尽可能的发现威胁转变为提高发现漏洞的准确率以及精度。

## 特点
- Cobra-W将提高漏洞发现的准确率以及精度。
- 提供更易于从代码层面定制审计思路的规则书写方式，更易于白帽子使用。
- 底层重写，支持windows、linux多平台。
- AST深度重写，多层语义解析、变量回溯，尽最大可能保证漏洞有效性。


## TODO
- <del>改写grep以及find，提供更好的底层支持</del>
- <del>去除不符合白帽子审计习惯的部分模式以及相关冗余代码</del>
- <del>重写rule规则方式</del>，改为更容易针对定制的方式（%30有待进一步优化）
- 重写AST
    - <del>递归回溯变量</del>
    - <del>递归回溯自定义函数</del>
    - <del>多级函数调用</del>
    - <del>自定义类调用</del>
    - 未知语法待解析
- ...


## 更新日志
- 2017-9-7
    - Cobra 2.0完成
    - 改写grep以及find，提供更好的底层支持
- 2017-9-7
    - Cobra-W 0.1完成
    - 去除相关冗余代码
- 2017-9-8
    - Cobra-W 0.1.1完成
    - 去除api以及cve部分代码
- 2017-9-18
    - Cobra-W 0.2完成
    - 新的rule规则
    - 重构完成
- 2017-9-27
    - Cobra-W 0.3完成
    - 重写rule分类，新增自定义处理配合初步ast
- 2017-10-12
    - Cobra-W 0.31完成
    - 深度AST分析第一部分完成，可递归遍历变量
- 2017-10-17
    - Cobra-W 0.32完成
    - 深度AST分析第一部分完善，递归自定义函数接近完成
- 2017-10-25
    - Cobra-W 0.33
    - 修复了一个issue，在处理if，else时候的bug
    - 更新了开发文档
- 2017-10-27
    - Cobra-W 0.4
    - 修复了CVI-1004的一部分致命bug
    - 更新了vustomize-match的多文件支持
- 2017-11-3
    - Cobra-W 0.5
    - 修复了issue#5
    - 更新了在递归变量时对数组的回溯
- 2017-11-22
    - Cobra-W 0.6
    - 修复了敏感语句在函数声明中回溯不正确的问题
    - 更新了全新的机制应用于敏感语句被封装于新函数的情况
- 2017-11-23
    - Cobra-W 0.6.1
    - 修复了生成新规则机制应用于function-param-regex
    - 更新了新的测试文件应对类变量回溯
- 2017-11-27
    - Cobra-W 0.7
    - 更新了全新的机制应用于类变量回溯，已完成大部分支持
- 2017-12-1
    - Cobra-W 0.7.1
    - 修复类变量回溯的多个bug，对类变量回溯已经有比较完整的支持
- 2017-12-7
    - Cobra-W 0.7.2
    - 修复处理BinaryOp节点时无法正确处理的bug
    - 部分修复了issue#9
    - 修复了对for节点以及if\else节点的支持


# README(开发文档)

```
cobra-w
├─cobra
├─docs
├─logs
├─result
├─rules
│  └─php
├─tests
   ├─ast
   │  └─test
   ├─examples
   └─vulnerabilities
```

- cobra: 核心代码目录
- docs: cobra-W文档目录
- logs: 扫描log储存位置
- result: 扫描结果储存位置（默认为.csv）
- rules: 规则目录
- tests： 测试代码目录


## 安装

首先需要安装依赖
```
pip install -r requirements.txt
```

然后扫描测试样例查看结果
```
python cobra.py -t ./tests/vulnerabilities/

python cobra.py -t ./tests/ast/
```


## 帮助

使用-h可以查看使用帮助

```
python .\cobra.py -h

usage: cobra [-h] [-t <target>] [-f <format>] [-o <output>] [-r <rule_id>]
             [-d] [--ast]

  ____      _                  __        __
 / ___|___ | |__  _ __ __ _    \ \      / /
| |   / _ \| '_ \| '__/ _` |    \ \ /\ / /
| |__| (_) | |_) | | | (_| | --- \ V  V /
 \____\___/|_.__/|_|  \__,_|      \_/\_/  v0.3.2

GitHub: https://github.com/LoRexxar/Cobra-W

Cobra is a static code analysis system that automates the detecting vulnerabilities and security issue.

optional arguments:
  -h, --help            show this help message and exit

Scan:
  -t <target>, --target <target>
                        file, folder, compress, or repository address
  -f <format>, --format <format>
                         vulnerability output format (formats: html, json, csv,
                        xml)
  -o <output>, --output <output>
                        vulnerability output STREAM, FILE
  -r <rule_id>, --rule <rule_id>
                        specifies rules e.g: 1000, 1001
  -d, --debug           open debug mode

Usage:
  python cobra.py -t tests/vulnerabilities
  python cobra.py -t tests/vulnerabilities -r 1000, 1001
  python cobra.py -t tests/vulnerabilities -f json -o /tmp/report.json
  python cobra.py -t tests/vulnerabilities --debug
```

## 核心代码

整个核心代码的运行逻辑：

```
__init__.py -> cli.py主线程 -> until.py加载规则库 -> detection.py 判断扫描对象的语言和框架 -> engine.py(scan) 启动扫描 -> cast.py ast -> parser.py ast分析 -> engine.py 整理结果 -> export.py 导出结果
```

- init.py：  参数的解析和对应配置
- cli.py:    开始扫描前的一些预处理
- cast.py:   ast中预处理的一些代码，如匹配函数获取变量名
- config.py: 一些配置文件目录的配置
- const.py:  一些常量的配置
- engine.py: 扫描主逻辑，处理扫描已经扫描结果处理
- export.py: 扫描结果的处理
- file.py:   底层文件操作的处理
- log.py:    log日志配置
- parser.py  AST核心文件
- rule.py    规则处理文件

## 规则模块

**规则模块现在问题超多...有待改进**

规则目录结构为
```
rules/{语言类型}/CVI_xxxx.py
```

在规则目录下，只有命名符合规定的规则会被成功加载，命名格式严格为`CVI_编号.py`

规则默认格式为
```
# -*- coding: utf-8 -*-

"""
    CVI-1000
    ~~~~

    Reflected XSS

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""


class CVI_1000():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1000
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "Reflected XSS"
        self.description = "Reflected XSS"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "echo|print|print_r|exit|die|printf|vprintf|trigger_error|user_error|odbc_result_all|ovrimos_result_all|ifx_htmltbl_result"

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass

```

**规则类必须和文件名相同，否则规则库会加载无效**

init里为规则的一部分设置
- svid: 规则编号
- language： 语言类型（会和扫描对象向匹配，使用对应的规则脚本）
- author: 规则作者
- vulnrability: 漏洞类型
- description: 漏洞描述
- statu: 表示是否开启该规则
- match_mode: 规则匹配方法（下面详解）
- match: 敏感函数正则，漏洞语句正则


### 规则匹配类型

暂时把规则匹配方法分为三类：

- only-regex
纯正则匹配，符合正则的点会直接被判定为漏洞点，不进入任何参数分析等...一个非常特殊的匹配模式。

- function-param-regex
函数正则匹配，通过匹配敏感函数来判断漏洞点，然后敏感函数中的所有变量会进入AST分析流程，如果匹配到其中参数可控，就会被判定为漏洞点。

- vustomize-match
自定义匹配，先通过正则匹配漏洞存在点，然后进入自定义的参数解析函数(规则中的main函数)，自定义解析到目标参数**列表**，返回进入ast分析，回溯可控变量。


### 预期

原Cobra是通过xml储存关键字，关键字匹配敏感函数，并通过匹配修复函数来判断漏洞点是否被修复。

Cobra-W希望能通过自定义代码来解决更复杂的情况，比如反序列化漏洞的锁定和修复判断。（现在这部分实现很差，几乎和原本的xml储存方式比没有优势，还增加了复杂性）

## 语法分析部分

语法分析的代码主要集中在case.py和parser.py两个文件，case主要负责处理AST的前期准备（参数确认）和AST分析后的结果处理。

核心的语法分析主要是parser.py。

整个分析过程依赖python的phply模块作语法分析，代码主要是对分析结果做处理。

```
test_single_file.php

<?php
include("test1.php");
include "test2.php";


# 不可控
$url = "phpinfo()";
eval($url);

# 可控
$url = $_GET['a'];
eval($url);

# 可控
eval($url2);

# 不可控
eval($url3);

# 经过一次
$url4 = $test;
eval($url4);

# 函数
 function test(){
     return $_GET['a'];
 }

$url5 = test();
eval($url5);


$a = 1;
if(a == 1){
    eval($url4);
}
```

上面的代码会被解析成相应的节点

```
Include('test1.php', False)
Include('test2.php', False)
Assignment(Variable('$url'), 'phpinfo()', False)
Eval(Variable('$url'))
Assignment(Variable('$url'), ArrayOffset(Variable('$_GET'), 'a'), False)
Eval(Variable('$url'))
Eval(Variable('$url2'))
Eval(Variable('$url3'))
Assignment(Variable('$url4'), Variable('$test'), False)
Eval(Variable('$url4'))
Function('test', [], [Return(ArrayOffset(Variable('$_GET'), 'a'))], False)
Assignment(Variable('$url5'), FunctionCall('test', []), False)
Eval(Variable('$url5'))
Assignment(Variable('$a'), 1, False)
If(BinaryOp('==', Constant('a'), 1), Block([Eval(Variable('$url4'))]), [], None)
```

节点列表会用倒序的方式逐步回溯目标变量

不同的变量会在analysis进入不同的处理函数

```
def analysis(nodes, vul_function, back_node, vul_lineo, file_path=None, function_params=None):
    """
    调用FunctionCall-->analysis_functioncall分析调用函数是否敏感
    :param nodes: 所有节点
    :param vul_function: 要判断的敏感函数名
    :param back_node: 各种语法结构里面的语句
    :param vul_lineo: 漏洞函数所在行号
    :param function_params: 自定义函数的所有参数列表
    :param file_path: 当前分析文件的地址
    :return:
    """
    buffer_ = []
    for node in nodes:
        if isinstance(node, php.FunctionCall):  # 函数直接调用，不进行赋值
            anlysis_function(node, back_node, vul_function, function_params, vul_lineo, file_path=file_path)

        elif isinstance(node, php.Assignment):  # 函数调用在赋值表达式中
            if isinstance(node.expr, php.FunctionCall):
                anlysis_function(node.expr, back_node, vul_function, function_params, vul_lineo, file_path=file_path)

            if isinstance(node.expr, php.Eval):
                analysis_eval(node.expr, vul_function, back_node, vul_lineo, function_params, file_path=file_path)

            if isinstance(node.expr, php.Silence):
                buffer_.append(node.expr)
                analysis(buffer_, vul_function, back_node, vul_lineo, file_path, function_params)

        elif isinstance(node, php.Print) or isinstance(node, php.Echo):
            analysis_echo_print(node, back_node, vul_function, vul_lineo, function_params, file_path=file_path)

        elif isinstance(node, php.Silence):
            nodes = get_silence_params(node)
            analysis(nodes, vul_function, back_node, vul_lineo, file_path)

        elif isinstance(node, php.Eval):
            analysis_eval(node, vul_function, back_node, vul_lineo, function_params, file_path=file_path)

        elif isinstance(node, php.Include) or isinstance(node, php.Require):
            analysis_file_inclusion(node, vul_function, back_node, vul_lineo, function_params, file_path=file_path)

        elif isinstance(node, php.If):  # 函数调用在if-else语句中时
            analysis_if_else(node, back_node, vul_function, vul_lineo, function_params, file_path=file_path)

        elif isinstance(node, php.While) or isinstance(node, php.For):  # 函数调用在循环中
            if isinstance(node.node, php.Block):
                analysis(node.node.nodes, vul_function, back_node, vul_lineo, file_path, function_params)

        elif isinstance(node, php.Function) or isinstance(node, php.Method):
            function_body = []
            function_params = get_function_params(node.params)
            analysis(node.nodes, vul_function, function_body, vul_lineo, function_params=function_params, file_path=file_path)

        elif isinstance(node, php.Class):
            analysis(node.nodes, vul_function, back_node, vul_lineo, file_path, function_params)

        back_node.append(node)
```

经过多级处理后，最终会进入变量的处理位置，`analysis_variable_node`调用`deep_parameters_back`进入深度递归回溯变量。

递归过程主要是`parameters_back`函数，仍然是倒序寻找变量赋值语句，然后左值保留，右值作为可控变量再次进入`parameters_back`函数。经过多层递归之后，就可以获得结果了。

### 预期

原Cobra这部分代码刚刚实现，仍只支持AST当前文件，为了处理多文件，我选择在无法获取当前变量赋值语句的情况下，回溯include类型语句，然后获取页面内容，获取新的节点，进入新一轮的递归。

目前已知的问题是
- 自定义的类处理不完整
- ...

更多问题还没遇到，需要更多样本做处理

