<?php
use GMO\GoogleAuth\Authentication;
use GMO\GoogleAuth\GroupsAuthorization;
use Symfony\Component\HttpFoundation\Session\Session;
use GMO\Common\Session\JwtCookieSessionStorage;
use GMO\Common\Session\AutoSavingAttributeBag;

require __DIR__ . '/../vendor/autoload.php';

$config = json_decode(file_get_contents(__DIR__ . '/config.json'), true);

$sessionStorage = new JwtCookieSessionStorage(
	$config['jwt']['cookieName'],
	$config['jwt']['secret']
);
$attributeBag = new AutoSavingAttributeBag($sessionStorage);
$session = new Session($sessionStorage, $attributeBag);
$authentication = new Authentication(
	$session,
	$config['oAuth']['clientId'],
	$config['oAuth']['clientSecret'],
	$config['oAuth']['redirectUri']
);

if(isset($_REQUEST['logout'])) {
	$authentication->logout();
}

if(!$authentication->isUserLoggedIn()) {
	echo '<a href="'.$authentication->getLoginUrl().'">Login</a>';
	exit();
}

$user = $authentication->getUser();

$groupsAuthorization = new GroupsAuthorization(
	$config['serviceAccount']['clientEmail'],
	$config['serviceAccount']['privateKeyPath'],
	$config['serviceAccount']['adminUser'],
	$config['serviceAccount']['domain']
);

if(!$groupsAuthorization->isUserInAnyGroup($user, $config['authorizationGroups'])) {
	$authentication->logout();
	echo '<a href="'.$authentication->getLoginUrl().'">Login</a>';
	exit();
}

echo "You are logged-in as " . $user->getEmail()
	. "<br /><a href=\"examples/authenticationAndAuthorization.php?logout\">Logout</a>";



