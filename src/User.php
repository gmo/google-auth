<?php
namespace GMO\GoogleAuth;


class User {
	public function __construct(array $attributes) {
		$this->attributes = $attributes;
		if(isset($this->attributes['payload']) && isset($this->attributes['payload']['email'])) {
			$this->email = $this->attributes['payload']['email'];
		} else {
			$this->email = NULL;
		}
	}

	public function getEmail() {
		return $this->email;
	}

	/** @var array */
	protected $attributes;
	protected $email;
} 