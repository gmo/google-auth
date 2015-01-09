<?php
namespace GMO\GoogleAuth\Session;

use GMO\Common\Collection;

class NativeSession implements SessionInterface {
	public function __construct() {
		session_start();

		if(!is_array($_SESSION)) {
			$_SESSION = array();
		}
	}

	public function get($field) {
		return Collection::get($_SESSION, $field, NULL);
	}

	public function delete($field) {
		if(Collection::containsKey($_SESSION, $field)) {
			unset($_SESSION[$field]);
		}
	}


	public function set($field, $value) {
		$_SESSION[$field] = $value;
	}
} 