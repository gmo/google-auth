<?php
namespace GMO\GoogleAuth\Session;

// TODO: Replace with Symfony sessions.  Make the implementations of this class implement Symfony SessionHandlerInterface
interface SessionInterface {
	public function get($field);
	public function set($field, $value);
	public function delete($field);
} 