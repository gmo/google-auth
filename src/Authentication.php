<?php
namespace GMO\GoogleAuth;

use Symfony\Component\HttpFoundation\Session\Session;
use GMO\GoogleAuth\Exception;
use Google_Client;
use Google_Config;
use Google_Auth_AssertionCredentials;
use Google_Auth_Exception;

class Authentication {
	public function __construct(Session $session, $clientId, $clientSecret, $redirectUri) {
		$this->session = $session;
		if(!$this->session->isStarted()) {
			$this->session->start();
		}

		$config = new Google_Config();
		$config->setClientId($clientId);
		$config->setClientSecret($clientSecret);
		$config->setRedirectUri($redirectUri);

		$this->userClient = new Google_Client($config);
		$this->userClient->setScopes(static::EMAIL_SCOPE);

		$this->checkForUserLoginAttempt();
		$this->setAccessTokenIfUserIsLoggedIn();
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

	public function setServiceAccount($clientEmail, $privateKeyPath, $adminUser) {
		$credentials = new Google_Auth_AssertionCredentials(
			$clientEmail,
			array(
				GroupsAuthorization::GROUP_SCOPE,
				GroupsAuthorization::USER_SCOPE
			),
			file_get_contents($privateKeyPath)
		);
		$credentials->sub = $adminUser;

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

	protected function setAccessTokenIfUserIsLoggedIn() {
		if(!$this->isUserLoggedIn()) {
			return;
		}

		$this->userClient->setAccessToken($this->getAccessTokenFromSession());
		try {
			$this->userClient->verifyIdToken();
		} catch(Google_Auth_Exception $e) {
			$this->session->set(static::USER_ACCESS_TOKEN_SESSION_KEY, null);
		}
	}

	/** @var Session */
	protected $session;

	/** @var \Google_Client */
	protected $userClient;

	/** @var \Google_Client */
	protected $serviceClient;

	const EMAIL_SCOPE = 'email';
	const USER_SETTINGS_SESSION_KEY = 'userSettings';
	const USER_ACCESS_TOKEN_SESSION_KEY = 'userAccessToken';
}