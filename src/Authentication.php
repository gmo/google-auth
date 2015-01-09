<?php
namespace GMO\GoogleAuth;

use GMO\GoogleAuth\Session\SessionInterface;
use GMO\GoogleAuth\Exception;
use Google_Client;
use Google_Config;

class Authentication {
	public function __construct(SessionInterface $session, $clientId, $clientSecret, $redirectUri) {
		$this->session = $session;

		$config = new Google_Config();
		$config->setClientId($clientId);
		$config->setClientSecret($clientSecret);
		$config->setRedirectUri($redirectUri);

		$this->googleClient = new Google_Client($config);
		$this->googleClient->setScopes('email');
		// TODO: Add relevant scopes here with $this->googleClient->addScope()

		$this->checkForUserLoginAttempt();

		if($this->isUserLoggedIn()) {
			$this->googleClient->setAccessToken($this->getAccessTokenFromSession());
		}
	}

	public function getLoginUrl() {
		return $this->googleClient->createAuthUrl();
	}

	public function isUserLoggedIn() {
		return $this->getAccessTokenFromSession() ? true : false;
	}

	public function getUser() {
		if(!$this->isUserLoggedIn()) {
			throw new Exception\UserNotLoggedIn();
		}

		$userAttributes = $this->googleClient->verifyIdToken()->getAttributes();

		return new User($userAttributes);
	}

	public function getAuthorizationListFromGroups(array $groups) {

	}

	public function setServiceAccount() {

	}

	protected function getAccessTokenFromSession() {
		return $this->session->get(static::USER_ACCESS_TOKEN_SESSION_KEY);
	}

	protected function checkForUserLoginAttempt() {
		if(isset($_GET['error'])) {
			throw new Exception\LoginError($_GET['error']);
		}

		if(!isset($_GET['code'])) {
			return;
		}

		$this->googleClient->authenticate($_GET['code']);
		$this->session->set(static::USER_ACCESS_TOKEN_SESSION_KEY, $this->googleClient->getAccessToken());
	}

	/** @var SessionInterface */
	protected $session;

	/** @var \Google_Client */
	protected $googleClient;

	const USER_SETTINGS_SESSION_KEY = 'userSettings';
	const USER_ACCESS_TOKEN_SESSION_KEY = 'userAccessToken';
}