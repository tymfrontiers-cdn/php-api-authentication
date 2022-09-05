<?php
namespace TymFrontiers\API;
use \TymFrontiers\MultiForm,
    \TymFrontiers\MySQLDatabase;

class Authentication{

  private $_sign_pattern = [];
  private $_app=false;
  private $_conn = false;
  private $_access=[];
  private $_signature_method;
  public $errors = [];

  function __construct(array $api_sign_patterns = [], string $custom_header_set='', int $overtime_seconds=0, bool $skip_app_log = false, $conn = false){
    global $database;
    if ((!$conn || !$conn instanceof MySQLDatabase) && !$database instanceof MySQLDatabase) {
      throw new \Exception("No database connection set", 1);
    }
    $this->_conn = $conn ? $conn : $database;
    $this->_sign_pattern = $api_sign_patterns;
    $custom_header_sets = [
      'get' => $_GET,
      'post' => $_POST
    ];
    $header = (!empty($custom_header_set) && \array_key_exists(\strtolower($custom_header_set),$custom_header_sets))
      ? $custom_header_sets[$custom_header_set]
      : \apache_request_headers();
    $missn = [];
    foreach ([
      'Auth-App',
      'Auth-Key',
      'Signature-Method',
      'Tymstamp',
      'Auth-Signature'
    ] as $prop) {
      if (!\array_key_exists($prop, $header)) {
        $missn[] = $prop;
      }
    }
    if( empty($missn) && \in_array(\strtolower($header["Signature-Method"]), ['sha256','sha512'])) {
      $header['Signature-Method'] = \strtolower($header['Signature-Method']);
      $db_name = \function_exists("\get_database")
        ? \get_database("developer")
        : (\defined("MYSQL_DEV_DB") ? MYSQL_DEV_DB : "");
      if (empty($db_name)) throw new \Exception("Dev database: 'MYSQL_DEV_DB' not defined", 1);
      
      $dev_mode = \defined("API_ENV_DEVMODE") ? (bool)API_ENV_DEVMODE : false;
      $app = new DevApp($this->_conn, $db_name);
      $app->load($header['Auth-App'], $header['Auth-Key'], !(bool)$dev_mode);

      if( !empty($app->name) ){
        if ($app->isSystem() && !$dev_mode) {
          $this->errors['self'][] = [0,256,"System apps/users can only be used in development environment.",__FILE__,__LINE__]; 
        } else {
          $hash_string = "{$app->prefix}&{$app->name}&{$app->privateKey()}&{$header['Signature-Method']}&{$header['Tymstamp']}";
          $sign = \base64_decode($header['Auth-Signature']);
          $hash = \hash($header['Signature-Method'],$hash_string);
          // $set_expiry = \strtotime("+" . \ini_get("max_execution_time") . " Seconds");
          $request_expiry = \strtotime("+" . \ini_get("max_execution_time") . " Seconds", (int)$header['Tymstamp']);
          if ($overtime_seconds > 0 && $dev_mode) {
            $request_expiry += $overtime_seconds;
          }
          if( $sign == $hash){
            if( $request_expiry >= \time() ){
              $this->_app = $app;
              $this->_signature_method = $header['Signature-Method'];
              // save log
              if (!$dev_mode || ($dev_mode && !$skip_app_log) ) {
                try {
                  $log = new MultiForm($db_name, 'request_history', 'id', $this->_conn);
                  $log->app = $this->appName();
                  $log->path = "{$_SERVER['REQUEST_URI']} | {$_SERVER["HTTP_HOST"]}";
                  $post = \json_decode(\file_get_contents('php://input'), true);
                  $post = $post ? $post : (!empty($_POST) ? ($_POST) : $_GET);
                  $re_param = $post;
                  if (!empty($re_param)) {
                    $log->param = \json_encode($re_param);
                  }
                  $log->create();
                } catch (\Exception $e) {
                  throw new \Exception("Failed to save Log: ".$e->getMessage(), 1);
                }
              }
  
            } else {
              $this->errors['self'][] = [0,256,"Request Authentication credential expired",__FILE__,__LINE__];
            }
          } else {
            $this->errors['self'][] = [0,256,"Request signature failed to authenticate.",__FILE__,__LINE__];
          }
        }
      }else{
        $this->errors['self'][] = [0,256,"Invalid/Inactive: App/credential.",__FILE__,__LINE__];
      }
    }else{
      $this->errors['self'][] = [0,256,"Missing Auth parameters: ".\implode(", ", $missn). ". Accepted Signature-Method: ".\implode(", ", ['sha256','sha512']),__FILE__,__LINE__];
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
