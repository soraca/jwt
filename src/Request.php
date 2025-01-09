<?php
declare(strict_types = 1);

namespace Soraca\Jwt;

class Request
{
    // 主机
    public $host;
    // 请求方式
    public $method = 'get';
    // 请求路由
    public $route;
    // 请求地址
    public $url;
    // 链接超时
    public $connect_timeout = 10;
    public $scheme = 'http';
    public $header = [];
    // 时间戳
    public $time_stamp;
    // 签名
    public $sign;
    // 签名类型
    public $sign_type = 'HMAC-SHA256';

    public $params;


    public function __construct()
    {
        $this->time_stamp = time();
    }

    /*
     * 主机或者域名
     * */
    public function host($host)
    {
        $this->host = $host;
        return $this;
    }

    /*
     * 请求方式
     * */
    public function method($method = 'get')
    {
        $this->method = $method;
        return $this;
    }

    /*
     * 请求头部
     * */
    public function header($header = [])
    {
        $this->header = array_merge([
            'Content-type:application/json;charset=utf-8',
            'Accept:application/json',
        ], $header);
        $this->header = $header;
        return $this;
    }

    /*
     * 请求参数
     * */
    public function params($params = [])
    {
        $this->params = $params;
        return $this;
    }

    public function route($route)
    {
        $this->route = $route;
        return $this;
    }

    /*
     * 签名类型
     * @params string $sign_type 类型：sha256、sha512和md5
     * */
    public function signType($sign_type = 'md5')
    {
        $this->sign_type = $sign_type;
        return $this;
    }

    /*
     * 发起请求
     * */
    public function request()
    {
        $this->url = $this->host . $this->route;
        # 数据验证

        # 创建签名
        //$this->params['sign'] = $this->createSign($this->params);

        # 数据请求
        $result = $this->curl($this->url, $this->params, $this->method, $this->header);
        return $result;
    }

    /*
     * 创建签名
     * @desc $sign_type 支持sha256、hmacmd5、hmacsha1、hmacsha256
     * */
    private function createSign($params = [])
    {
        // 删除原有参数
        $params['time_stamp'] = $this->time_stamp;
        //$params['access_key_id'] = $this->header;
        // 参数排序
        ksort($params);
        // 数组转字符串
        $signString = http_build_query($params);
        // 使用哈希函数生成签名 支持sha256、sha512和md5
        $signature = hash($this->sign_type, $signString);

        $this->sign = $signature;
        return $signature;
    }

    /*
     * 数据效验
     * */
    private function validate()
    {

    }

    /*
     * Curl请求
     * @params string $url 请求地址
     * @params array $data 请求数据
     * @params string $method 请求方式
     * @params array $headerParams 请求头部
     * @return array|string
     * */
    private function curl($url, $data = [], $method = 'get', $header = [])
    {
        $start_time = microtime(true);
        /*  $header = [
              // "Content-type:application/json;charset='utf-8'",   // step 1 $data 必须为json格式组格式
              "Accept:application/json"
          ];
          if (!empty($headerParams)) {
              $header = $headerParams;
          }*/
        //print_r($header);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->connect_timeout);                  // 设置超时时间 10s

        // 以post发送数据
        if ($method == 'post') {
            curl_setopt($ch, CURLOPT_POST, 1);                      //声明使用POST方式来进行发送
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);            //step 1.1发送什么数据呢
        }

        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

        $output = curl_exec($ch);
        curl_close($ch);

        // 网络链接失败
        if ($output == false) {
            $output = json_encode(['code' => 404, 'msg' => 'Network connection failure'], JSON_UNESCAPED_UNICODE);
        }

        $result = json_decode($output, true);
        if (json_last_error() == JSON_ERROR_NONE) {
            # 转数组
            // 结束时间
            $end_time = microtime(true);
            $use_time = round($end_time - $start_time, 3);
            // api耗时
            $result['use_time'] = $use_time;
            return $result;

        } else {
            # 非json格式，返回原数据
            return $output;
        }
    }


}