<html>
<body>
<h1>Authentication ADFS with OpenIDConnect : Authorization code Grant Flow</h1>
<a href="https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios">Client Configuration Reference</a>

<?php

require_once('vendor/autoload.php');
/*require_once("vendor/firebase/php-jwt/src/BeforeValidException.php");
require_once("vendor/firebase/php-jwt/src/ExpiredException.php");
require_once("vendor/firebase/php-jwt/src/JWT.php");
require_once("vendor/firebase/php-jwt/src/SignatureInvalidException.php");*/
use \Firebase\JWT\JWT;
JWT::$leeway = 60;

session_start();

function http($url, $params=false) {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  if($params)
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
  return json_decode(curl_exec($ch));
}

function getPublicKey($adfs_metadata){
  if(isset($adfs_metadata)){
    $obj = new StdClass();
    $jwks = http($adfs_metadata->jwks_uri);
    if(isset($jwks)){
      $key_obj = $jwks->keys[0];
      $obj->alg = $key_obj->alg;
      $publicKeyInfoBase64 = $key_obj->x5c[0];    
      $encoding = "-----BEGIN CERTIFICATE-----\n";
      $offset = 0;
      while ($segment=substr($publicKeyInfoBase64, $offset, 64)){
         $encoding = $encoding.$segment."\n";
         $offset += 64;
      }
      $encoding = $encoding."-----END CERTIFICATE-----\n";
      $obj->x5c = $encoding;
      return $obj;
    }
  }
  else{
    echo "No metadata";
    die();
  }
}

//========================  IDP Configuration ===========================
$client_id = 'example_client_id';
$client_secret = 'example_client_secret';
$resource = 'example_resource_id';
$redirect_uri = 'http://example.application.com';
$metadata_url = 'https://example.adfs.com/adfs/.well-known/openid-configuration';
//=======================================================================

$metadata = http($metadata_url);

if(!isset($_SESSION['token'])) {

  if(isset($_POST['code'])) {

    if($_SESSION['state'] != $_POST['state']) {
      die('Authorization server returned an invalid state parameter');
    }

    if(isset($_GET['error'])) {
      die('Authorization server returned an error: '.htmlspecialchars($_GET['error']));
    }

    $response = http($metadata->token_endpoint, [
      'grant_type' => 'authorization_code',
      'code' => $_POST['code'],
      'redirect_uri' => $redirect_uri,
      'client_id' => $client_id,
      'client_secret' => $client_secret,
    ]);

    if(isset($response->access_token)){
      try{
        $public_key = getPublicKey($metadata);
        $access_token = $response->access_token;
        $token = JWT::decode($access_token, $public_key->x5c, array($public_key->alg));
        $_SESSION['token'] = $token;
        header('Location: /login_example.php');
        die();
      }
      catch(Exception $e){
        die($e);
      }
    }
    elseif(isset($response->error)){
      die('<span style="color:red">Authentication failed</span>: Error: '.$response->error_description);
    }
    else{
      die('Error fetching access token');
    }
  }
  else{

    if(isset($_POST['error'])){
      $_SESSION['token'] = 'error';
      echo '<br /><span style="color:red">Error: '.$_POST['error'].'</span><br />';
      echo $_POST['error_description'];
      echo '<br/><br/><p><a href="/login_example.php?logout">Log Out</a></p>';
    }
    else{

      $_SESSION['state'] = bin2hex(random_bytes(32));

      $authorize_url = $metadata->authorization_endpoint.'?'.http_build_query([
        'response_type' => 'code',
        'resource' => $resource,
        'client_id' => $client_id,
        'redirect_uri' => $redirect_uri,
        'response_mode' => 'form_post',
        'state' => $_SESSION['state'],
        'scope' => 'allatclaims'
      ]);
      echo '<p>Not logged in</p>';
      echo '<p><a href="'.$authorize_url.'">Log In</a></p>';
    }
  }
}
else{
  $token = $_SESSION['token'];

  echo '<p>Logged in as</p>';
  echo '<p>' . $token->unique_name . '</p>';
  echo '<p><a href="/login_example.php?logout">Log Out</a></p>';
  if(isset($token)){
    $json_token = json_encode($token);
    echo str_replace(',',',<br/>',$json_token);
  }

  if(isset($_GET['logout'])) {
    unset($_SESSION['token']);
    $signout_url = $metadata->end_session_endpoint.'?'.http_build_query([
      'post_logout_redirect_uri' => $redirect_uri
    ]);
    header('Location: '.$signout_url);
  }

  die();
}
?>