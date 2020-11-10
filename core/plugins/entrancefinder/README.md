# 插件 EntranceFinder

一个有趣的小工具，用于解决在审计大量的php代码时，快速发现存在可能的入口页面（或是开发者都遗漏的）。

通过非常简单的处理AST逻辑去除了只有声明代码的页面，
通过调整-l参数可以获取更精确有效的结果，且通过简单的相似页面判断算法，还会展示相对应的相似页面，大幅提高代码审计的前置效率。

使用熟练的小伙伴可以通过设置-b来剔除鉴权代码等，用于更精确的发现入口文件

## Usage
```
 _   __            _                      ___  ___
| | / /           | |                     |  \/  |
| |/ / _   _ _ __ | |    _   _ _ __       | .  . |
|    \| | | | '_ \| |   | | | | '_ \ _____| |\/| |
| |\  \ |_| | | | | |___| |_| | | | |_____| |  | |
\_| \_/\__,_|_| |_\_____/\__,_|_| |_|     \_|  |_/  -v2.0 beta4

GitHub: https://github.com/LoRexxar/Kunlun-M

KunLun-M is a static code analysis system that automates the detecting vulnerabilities and security issue.

Plugins list:
  entrance_finder                                   Quickly find the php entry page
  php_unserialize_chain_tools                       Discover the PHP deserialization chain through codedb

positional arguments:
  {entrance_finder,php_unserialize_chain_tools}
                        enter plugin name

optional arguments:
  -h, --help            show this help message and exit
  -t <target>, --target <target>
                        file, folder
  -d, --debug           open debug mode
  -l LIMIT, --limit LIMIT
                        limit node number(default 2)
  -b BLACKWORDS, --blackwords BLACKWORDS
                        set blacklist for scan
```


```
python3 .\kunlun.py plugin entrance_finder -t {target_path} -l 3
```

## tests

![](../../../docs/entrancefinder.png)