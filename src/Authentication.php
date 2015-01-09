<?php
namespace GMO\GoogleAuth;

use GMO\GoogleAuth\Session\SessionInterface;
use GMO\GoogleAuth\Exception;
use Google_Client;
use Google_Config;
use Google_Auth_AssertionCredentials;

class Authentication {
	public function __construct(SessionInterface $session, $clientId, $clientSecret, $redirectUri) {
		$this->session = $session;

		$config = new Google_Config();
		$config->setClientId($clientId);
		$config->setClientSecret($clientSecret);
		$config->setRedirectUri($redirectUri);

		$this->userClient = new Google_Client($config);
		$this->userClient->setScopes(static::EMAIL_SCOPE);
		// TODO: Add relevant scopes here with $this->googleClient->addScope()

		$this->checkForUserLoginAttempt();

		if($this->isUserLoggedIn()) {
			$this->userClient->setAccessToken($this->getAccessTokenFromSession());
		}
	}

	public function getLoginUrl() {
		return $this->userClient->createAuthUrl();
	}

	public function isUserLoggedIn() {
		return $this->getAccessTokenFromSession() ? true : false;
	}

	public function getUser() {
		if(!$this->isUserLoggedIn()) {
			throw new Exception\UserNotLoggedIn();
		}

		$userAttributes = $this->userClient->verifyIdToken()->getAttributes();

		return new User($userAttributes);
	}

	public function setServiceAccount($clientEmail, $privateKeyPath) {
		$credentials = new Google_Auth_AssertionCredentials(
			$clientEmail,
			array(GroupsAuthorization::READ_GROUP_SCOPE),
			file_get_contents($privateKeyPath)
		);

		$this->serviceClient = new Google_Client();
		$this->serviceClient->setAssertionCredentials($credentials);
		if ($this->serviceClient->getAuth()->isAccessTokenExpired()) {
			$this->serviceClient->getAuth()->refreshTokenWithAssertion();
		}
	}

	public function getUserClient() {
		return $this->userClient;
	}

	public function getServiceClient() {
		return $this->serviceClient;
	}

	protected function getAccessTokenFromSession() {
		return $this->session->get(static::USER_ACCESS_TOKEN_SESSION_KEY);
	}

	protected function checkForUserLoginAttempt() {
		$sessionAccessToken = $this->getAccessTokenFromSession();
		if(!empty($sessionAccessToken)) {
			return;
		}

		if(isset($_GET['error'])) {
			throw new Exception\LoginError($_GET['error']);
		}

		if(!isset($_GET['code'])) {
			return;
		}

		$this->userClient->authenticate($_GET['code']);
		$this->session->set(static::USER_ACCESS_TOKEN_SESSION_KEY, $this->userClient->getAccessToken());
	}

	/** @var SessionInterface */
	protected $session;

	/** @var \Google_Client */
	protected $userClient;

	/** @var \Google_Client */
	protected $serviceClient;

	const EMAIL_SCOPE = 'email';
	const USER_SETTINGS_SESSION_KEY = 'userSettings';
	const USER_ACCESS_TOKEN_SESSION_KEY = 'userAccessToken';
}