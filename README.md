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
- 添加Web管理端，通过Web端，可以设置扫描任务，查看扫描log，查看代码。
- 添加疑似漏洞分级，部分回溯存在问题但是不能回溯到可控变量的漏洞，通过疑似漏洞的方式展示。



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
- 2017-12-22
    - Cobra-W 0.7.3
    - 修复了部分处理ast的bug
    - 完善了cvi-1009
- 2017-12-27
    - Cobra-W 0.8
    - 全新的secret机制，自定义解决不同cms的过滤不一，导致的扫描误差大问题
    - 更新修复了判断是否被修复的问题
- 2017-12-28
    - Cobra-W 0.8.1
    - 修复了secret机制对auto rule的支持
- 2018-01-09
    - Cobra-W 0.8.2
    - 修复了部分bug
    - 添加部分debug log用于调试
- 2018-01-12
    - Cobra-W 0.8.3
    - 修复了python3支持

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


