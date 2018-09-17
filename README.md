<big>**写在最前，Cobra-W仍然处于测试开发阶段，未发布正式版本，谨慎应用...**</big>

# Cobra-W
[![GitHub (pre-)release](https://img.shields.io/github/release/LoRexxar/Cobra-W/all.svg)](https://github.com/LoRexxar/Cobra-W/releases)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://github.com/wufeifei/cobra/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/LoRexxar/Cobra-W.svg?branch=master)](https://travis-ci.org/LoRexxar/Cobra-W)
[![Coverage Status](https://coveralls.io/repos/github/LoRexxar/Cobra-W/badge.svg?branch=master)](https://coveralls.io/github/LoRexxar/Cobra-W?branch=master)

## Introduction
Cobra是一款**源代码安全审计**工具，支持检测多种开发语言源代码中的**大部分显著**的安全问题和漏洞。
[https://github.com/wufeifei/cobra](https://github.com/wufeifei/cobra)

Cobra-W是从Cobra2.0发展而来的分支，将工具重心从尽可能的发现威胁转变为提高发现漏洞的准确率以及精度。


## 特点

与其他代码审计相比：
- 静态分析，环境依赖小。
- 语义分析，对漏洞有效性判断程度更深。
- 多种语言支持。
- 开源python实现，更易于二次开发。


与Cobra相比：
- 深度重写AST，大幅度减少漏洞误报率。
- 提供更易于从代码层面定制审计思路的规则书写方式，更易于白帽子使用，易于拓展。
- 底层api重写，支持windows、linux等多平台。
- 多层语义解析、函数回溯，secret机制，新增多种机制应用于语义分析。


## TODO
- <del>改写grep以及find，提供更好的底层支持</del>
- <del>去除不符合白帽子审计习惯的部分模式以及相关冗余代码</del>
- <del>重写rule规则方式</del>，改为更容易针对定制的方式（有待进一步优化）
- 重写AST
    - <del>递归回溯变量</del>
    - <del>递归回溯自定义函数</del>
    - <del>多级函数调用</del>
    - <del>自定义类调用</del>
    - 未知语法待解析
- 添加Web管理端，通过Web端，可以设置扫描任务，查看扫描log，查看代码。
- 添加疑似漏洞分级，部分回溯存在问题但是不能回溯到可控变量的漏洞，通过疑似漏洞的方式展示。


## 更新日志

[changelog.md](./docs/changelog.md)


# README

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
```
## 开发文档

[dev.md](./docs/dev.md)

## Contributors

感谢如下贡献者对本工具发展过程中的贡献：
- Knownsec 404 Team [LoRexxar](https://github.com/LoRexxar)
- 北邮天枢 [Sissel](https://github.com/boke1208)