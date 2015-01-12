<?php
namespace GMO\GoogleAuth;

use Symfony\Component\HttpFoundation\Session\Session;
use GMO\GoogleAuth\Exception;
use Google_Client;
use Google_Config;
use Google_Auth_AssertionCredentials;
use Google_Auth_Exception;

class Authentication {

	/**
	 * Constructor.
	 * @param Session $session
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $redirectUri
	 */
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

	/**
	 * Gets the Google OAuth2 login url
	 * @return string
	 */
	public function getLoginUrl() {
		return $this->userClient->createAuthUrl();
	}

	/**
	 * Checks if the user is logged-in already
	 * @return bool
	 */
	public function isUserLoggedIn() {
		return $this->getAccessTokenFromSession() ? true : false;
	}

	/**
	 * Logs the user out
	 */
	public function logout() {
		if(!$this->isUserLoggedIn()) {
			return;
		}

		$this->session->remove(static::USER_ACCESS_TOKEN_SESSION_KEY);
	}

	/**
	 * Gets a User object representing the currently logged-in user.
	 * @return User
	 * @throws Exception\UserNotLoggedIn
	 */
	public function getUser() {
		if(!$this->isUserLoggedIn()) {
			throw new Exception\UserNotLoggedIn();
		}

		$userAttributes = $this->userClient->verifyIdToken()->getAttributes();
		return new User($userAttributes);
	}

	/**
	 * Sets the service account for use with Google account-wide APIs
	 * @param string $clientEmail
	 * @param string $privateKeyPath A path to the private key to authenticate the service account with
	 * @param string $adminUser The admin user to impersonate during API calls
	 */
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

	/**
	 * Gets the Google client that uses OAuth2 for API calls
	 * @return Google_Client
	 */
	public function getUserClient() {
		return $this->userClient;
	}

	/**
	 * Gets the Google client that uses a Service Account for API Calls
	 * @return Google_Client
	 */
	public function getServiceClient() {
		return $this->serviceClient;
	}

	/**
	 * Gets the Google API token for the currently logged-in user's session
	 * @return mixed
	 */
	protected function getAccessTokenFromSession() {
		return $this->session->get(static::USER_ACCESS_TOKEN_SESSION_KEY);
	}

	/**
	 * Checks for a OAuth2 callback, and handle by either throwing errors or setting up the user's session
	 * @throws Exception\LoginError
	 */
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

	/**
	 * Sets the access token in the User Client if the user is logged-in properly
	 */
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
	const USER_ACCESS_TOKEN_SESSION_KEY = 'userAccessToken';
}