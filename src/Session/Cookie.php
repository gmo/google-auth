<?php
namespace GMO\GoogleAuth\Session;

use GMO\Common\Collection;
use JWT;

class Cookie implements SessionInterface {
	/**
	 * Constructor.
	 * @param string $cookieName
	 * @param string $secret Secret for encrypting/decrypting the JWT packet in the cookie
	 * @param string|null $cookieDomain
	 */
	public function __construct($cookieName, $secret, $cookieDomain = null) {
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
	 * Gets a value from the user's cookie
	 * @param string $field
	 * @return mixed
	 */
	public function get($field) {
		return Collection::get($this->values, $field, NULL);
	}

	/**
	 * Deletes a value from the user's cookie
	 * @param string $field
	 */
	public function delete($field) {
		if(Collection::containsKey($this->values, $field)) {
			unset($this->values[$field]);
		}
	}

	/**
	 * Sets a value in the user's cookie
	 * @param string $field
	 * @param mixed $value
	 */
	public function set($field, $value) {
		$this->values[$field] = $value;
		$this->rawCookie = JWT::encode($this->values, $this->secret);
		setcookie($this->cookieName, $this->rawCookie, null, "/", $this->cookieDomain);
	}

	/** @var string */
	protected $cookieName;
	/** @var null|string */
	protected $cookieDomain;
	/** @var string */
	protected $secret;
	/** @var string */
	protected $rawCookie;
	/** @var array */
	protected $values;
}