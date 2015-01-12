<?php
namespace GMO\GoogleAuth\SessionStorageHandler;

use SessionHandlerInterface;
use GMO\Common\Collection;
use JWT;

class JwtCookie implements SessionHandlerInterface {

	/**
	 * Constructor.
	 * @param string $cookieName
	 * @param string $secret Secret for encrypting/decrypting the JWT packet in the cookie
	 * @param string|null $cookieDomain
	 */
	public function __construct($cookieName, $secret, $cookieDomain = null) {
		$this->cookieName = $cookieName;
		$this->secret = $secret;
		$this->cookieDomain = $cookieDomain;
		$this->rawCookie = Collection::get($_COOKIE, $cookieName, '');

		try {
			$this->values = (array) JWT::decode($this->rawCookie, $this->secret);
		} catch(\Exception $e) {
			$this->values = array();
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function open($savePath, $sessionName) {
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function close() {
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function read($sessionId) {
		return Collection::get($this->values, $sessionId, '');
	}

	/**
	 * {@inheritdoc}
	 */
	public function write($sessionId, $data) {
		$this->values[$sessionId] = $data;
		$this->rawCookie = JWT::encode($this->values, $this->secret);
		$this->setCookie();
	}

	/**
	 * {@inheritdoc}
	 */
	public function destroy($sessionId) {
		if(Collection::containsKey($this->values, $sessionId)) {
			unset($this->values[$sessionId]);
		}
		$this->setCookie();
	}

	/**
	 * {@inheritdoc}
	 */
	public function gc($maxlifetime) {
		return true;
	}

	protected function setCookie() {
		setcookie($this->cookieName, $this->rawCookie, null, "/", $this->cookieDomain);
	}
}