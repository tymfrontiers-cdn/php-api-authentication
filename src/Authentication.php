<?php
namespace TymFrontiers\API;

class Authentication{

  private $_sign_pattern = [];
  private $_app=false;
  private $_access=[];
  private $_signature_method;
  public $errors = [];

  function __construct(array $api_sign_patterns = [], string $custom_header_set='', int $overtime_seconds=0){
    $this->_sign_pattern = $api_sign_patterns;
    $custom_header_sets = [
      'get' => $_GET,
      'post' => $_POST
    ];
    $header = (!empty($custom_header_set) && \array_key_exists(\strtolower($custom_header_set),$custom_header_sets))
      ? $custom_header_sets[$custom_header_set]
      : \apache_request_headers();
    if(
      \array_key_exists('Auth-App',$header) &&
      \array_key_exists('Auth-Key',$header) &&
      \array_key_exists('Signature-Method',$header) &&
      \array_key_exists('Tymstamp',$header) &&
      \array_key_exists('Auth-Signature',$header) &&
      \in_array( \strtolower($header['Signature-Method']),['sha256','sha512'])
    ){
      $header['Signature-Method'] = \strtolower($header['Signature-Method']);
      $app = new DevApp($header['Auth-App'],$header['Auth-Key'],true);
      if( !empty($app->name) ){
        $hash_string = "{$app->prefix}&{$app->name}&{$app->privateKey()}&{$header['Signature-Method']}&{$header['Tymstamp']}";
        $sign = \base64_decode($header['Auth-Signature']);
        $hash = \hash($header['Signature-Method'],$hash_string);
        $request_expiry = \strtotime($app->api_max_request_tym, (int)$header['Tymstamp']);
        if ($overtime_seconds > 0) {
          $request_expiry += $overtime_seconds;
        }
        if( $sign == $hash){
          if( $request_expiry >= \time() ){
            $this->_app = $app;
            $this->_signature_method = $header['Signature-Method'];
          }else{
            $this->errors['self'][] = [0,256,"Request Authentication credential expired",__FILE__,__LINE__];
          }
        }else{
          $this->errors['self'][] = [0,256,"Request signature failed to authenticate.",__FILE__,__LINE__];
        }
      }else{
        $this->errors['self'][] = [0,256,"Invalid/Inactive: App/credential.",__FILE__,__LINE__];
      }
    }else{
      $this->errors['self'][] = [0,256,"Missing Auth parameters encountered!",__FILE__,__LINE__];
    }
  }

  public function validApp(array $app_strict = []){
    return empty($app_strict)
      ? ($this->_app !== false)
      : ( ($this->_app !== false) && (\in_array($this->_app->name,$app_strict)) );
  }
  public function signature(string $path, array $values, string $private_key='', string $sign_meth='sha512'){
    if( \array_key_exists($path, $this->_sign_pattern) ){
      $private_key = !empty($private_key) ? $private_key : $this->_app->privateKey();
      $pattern = $this->_sign_pattern[$path];
      $hash_string = "{$this->_app->prefix}&{$private_key}";
      foreach($pattern as $key){
        if( !\array_key_exists($key,$values) ){
          throw new \Exception("Parameter/value pairs does not have required key(s).", 1);
        }else{
          $hash_string .= "&{$values[$key]}";
        }
      }
      $sign_meth = !empty($this->_signature_method) ? $this->_signature_method : $sign_meth;
      return \hash($sign_meth,$hash_string);
    }
    return null;
  }
  public function appName(){ return $this->_app->name; }
  public function appPuKey(){ return $this->_app->publicKey(); }

}
