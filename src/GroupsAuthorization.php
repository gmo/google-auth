<?php
namespace GMO\GoogleAuth;

use Google_Client;
use Google_Service_Directory;

class GroupsAuthorization {
	public function __construct(Authentication $authentication, $domain, array $groupEmailAddresses = array()) {
		$this->authentication = $authentication;
		$this->domain = $domain;

		if(!$this->authentication->getServiceClient() instanceof Google_Client) {
			throw new Exception\ServiceAccountMissing();
		}

		$this->service = new Google_Service_Directory($this->authentication->getServiceClient());

		$this->setGroupEmailAddresses($groupEmailAddresses);
	}

	public function getGroupEmailAddresses() {
		return $this->groupEmailAddresses;
	}

	public function isUserInAnyGroup(User $user) {

	}

	public function isUserInGroup(User $user, Group $group) {

	}

	public function setGroupEmailAddresses(array $groupEmailAddresses) {
		$this->groupEmailAddresses = $groupEmailAddresses;

		if(!empty($this->groupEmailAddresses)) {
			$this->buildGroupFromGroupEmailAddresses();
		}
	}

	public function getAllGroupsSummary() {
		// Calls "Retrieve all groups for a domain or the account"
		$groups = $this->service->groups->listGroups(array(
			'domain' => $this->domain
		));
		//$groups = $this->service->groups->get('devops@gmomail.org');
		var_dump($groups);
	}

	public function getGroupsForUser($userKey) {
		$this->getAllGroupsSummary();
		return $this->service->groups->listGroups(array(
			'userKey' => $userKey,
			'domain' => $this->domain,
		));
	}

	protected function buildGroupFromGroupEmailAddresses() {
		//$this->service->groups->get();

	}

	protected $authentication;
	protected $groupEmailAddresses;
	protected $domain;

	/** @var \Google_Service_Directory */
	protected $service;

	const READ_GROUP_SCOPE = 'https://www.googleapis.com/auth/admin.directory.group.readonly';
}