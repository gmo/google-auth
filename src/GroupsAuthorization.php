<?php
namespace GMO\GoogleAuth;

use Google_Client;
use Google_Service_Directory;
use Google_Service_Directory_Group;

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

	public function setGroupEmailAddresses(array $groupEmailAddresses) {
		$this->groupEmailAddresses = $groupEmailAddresses;
	}

	public function isUserInAnyGroup(User $user) {
		return $this->isUserInAnyProvidedGroup($user, $this->groupEmailAddresses);
	}

	public function isUserInProvidedGroup(User $user, $group) {
		return $this->isUserInAnyProvidedGroup($user, array($group));
	}

	public function isUserInAnyProvidedGroup(User $user, array $groupEmailAddresses) {
		$userGroups = $this->getGroupsEmailAddressesForUser($user->getEmail());
		$commonGroups = array_intersect($userGroups, $groupEmailAddresses);
		return !empty($commonGroups);
	}

	public function isUserInAllProvidedGroups(User $user, array $groupEmailAddresses) {
		$userGroups = $this->getGroupsEmailAddressesForUser($user->getEmail());
		$commonGroups = array_intersect($userGroups, $groupEmailAddresses);
		return count($groupEmailAddresses) === count($commonGroups);
	}

	public function getAllGroupsSummary() {
		return $this->service->groups->listGroups(array(
			'domain' => $this->domain
		));
	}

	public function getGroupsEmailAddressesForUser($userKey) {
		$groupEmails = array();
		$pageToken = null;

		do {
			$params = array(
				'userKey' => $userKey,
				'domain' => $this->domain,
			);
			if(!empty($pageToken)) {
				$params['pageToken'] = $pageToken;
			}
			$results = $this->service->groups->listGroups($params);

			$pageGroupEmails = array_map(function(Google_Service_Directory_Group $group) {
				return $group->getEmail();
			}, $results->getGroups());

			$groupEmails = array_merge($groupEmails, $pageGroupEmails);
			$pageToken = $results->getNextPageToken();
		} while(!empty($pageToken));

		return $groupEmails;
	}

	protected $authentication;
	protected $groupEmailAddresses;
	protected $domain;

	/** @var \Google_Service_Directory */
	protected $service;

	const USER_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user';
	const GROUP_SCOPE = 'https://www.googleapis.com/auth/admin.directory.group';
}